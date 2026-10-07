"""Pluggable local LLM transport.

Two backends behind one interface:

  * OllamaLLM — talks to a local Ollama server's OpenAI-compatible endpoint
    (http://localhost:11434/v1). No API key, no network beyond localhost.
    This is the real investigator; swap models with one string.

  * StubLLM — a deterministic, offline model used by tests, CI and the default
    demo. Per model it has a *per-run hit rate* and token/latency profile, so
    the cost-to-recall experiment produces an honest convergence curve without
    a GPU. A weak model misses more often per run; looped, its recall climbs.

The LLM is only ever the *investigator*: it reasons over a graph it did not
build and proposes which path to exploit. The deterministic validator decides
truth. So a hallucinating model cannot manufacture a VERIFIED finding.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import time
from dataclasses import dataclass

import httpx


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass
class LLMResult:
    text: str
    model: str
    usage: Usage
    wall_seconds: float


# Notional cloud $/1k tokens (output), used only to retell the Mythos
# cost-to-recall story alongside the real local metric (runs / wall-time).
# Local models cost ~0; these are reference prices, clearly labelled in charts.
PRICE_PER_1K_USD = {
    "frontier": 0.075,     # frontier-class single scan (expensive, reliable)
    "mid": 0.015,
    "cheap": 0.002,        # small model, run many times
    # concrete local names map onto tiers:
    "qwen2.5-coder:7b": 0.0,
    "qwen2.5-coder:1.5b": 0.0,
    "qwen2.5-coder:32b": 0.0,
}


class BaseLLM:
    name = "base"

    def complete(self, system: str, user: str, model: str | None = None,
                 temperature: float = 0.2, run_index: int = 0) -> LLMResult:
        raise NotImplementedError

    def available(self) -> bool:
        return True


class OllamaLLM(BaseLLM):
    name = "ollama"

    def __init__(self, base_url: str | None = None, default_model: str = "qwen2.5-coder:7b"):
        self.base_url = (base_url or os.environ.get(
            "OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.default_model = os.environ.get("PROOFTRACE_MODEL", default_model)

    def available(self) -> bool:
        """Reachable AND has at least one model pulled — otherwise `auto`
        should fall back to the deterministic stub rather than fail on a
        missing model."""
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=2.0)
            if r.status_code != 200:
                return False
            return len(r.json().get("models", [])) > 0
        except Exception:
            return False

    def complete(self, system: str, user: str, model: str | None = None,
                 temperature: float = 0.2, run_index: int = 0) -> LLMResult:
        model = model or self.default_model
        t0 = time.time()
        r = httpx.post(
            f"{self.base_url}/v1/chat/completions",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": temperature,
                "stream": False,
            },
            timeout=180.0,
        )
        r.raise_for_status()
        data = r.json()
        text = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        return LLMResult(
            text=text,
            model=model,
            usage=Usage(
                prompt_tokens=usage.get("prompt_tokens", _approx_tokens(system + user)),
                completion_tokens=usage.get("completion_tokens", _approx_tokens(text)),
            ),
            wall_seconds=time.time() - t0,
        )


# Per-model profile for the deterministic stub: (hit_rate, tier, in_tok, out_tok, latency_s)
STUB_PROFILES = {
    "qwen2.5-coder:32b": (0.92, "frontier", 1800, 420, 0.9),
    "qwen2.5-coder:7b": (0.55, "mid", 1700, 380, 0.4),
    "qwen2.5-coder:1.5b": (0.28, "cheap", 1650, 300, 0.15),
    # generic tiers if named directly
    "frontier": (0.92, "frontier", 1800, 420, 0.9),
    "mid": (0.55, "mid", 1700, 380, 0.4),
    "cheap": (0.28, "cheap", 1650, 300, 0.15),
}
DEFAULT_PROFILE = (0.55, "mid", 1700, 380, 0.4)


class StubLLM(BaseLLM):
    """Deterministic offline investigator with per-model reliability."""
    name = "stub"

    def __init__(self, seed: int = 1337):
        self.seed = seed

    def _rng(self, model: str, run_index: int, salt: str) -> random.Random:
        h = hashlib.sha256(f"{self.seed}:{model}:{run_index}:{salt}".encode()).hexdigest()
        return random.Random(int(h[:16], 16))

    def complete(self, system: str, user: str, model: str | None = None,
                 temperature: float = 0.2, run_index: int = 0) -> LLMResult:
        model = model or "qwen2.5-coder:7b"
        hit_rate, _tier, in_tok, out_tok, latency = STUB_PROFILES.get(model, DEFAULT_PROFILE)
        rng = self._rng(model, run_index, _digest(user))
        hit = rng.random() < hit_rate

        # The stub emits the same structured JSON the real prompt asks for.
        if hit and "candidate_paths" in user:
            payload = _hit_payload(user)
        elif "candidate_paths" in user:
            payload = _miss_payload(user, rng)
        else:
            payload = {"ack": True}

        text = json.dumps(payload)
        time.sleep(min(latency, 0.05) if os.environ.get("PROOFTRACE_FAST") else latency)
        return LLMResult(
            text=text,
            model=model,
            usage=Usage(prompt_tokens=in_tok, completion_tokens=out_tok),
            wall_seconds=latency,
        )


def _approx_tokens(s: str) -> int:
    return max(1, len(s) // 4)


def _digest(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:8]


def _extract_candidates(user: str) -> list[dict]:
    try:
        start = user.index("candidate_paths")
        brace = user.index("[", start)
        depth, i = 0, brace
        while i < len(user):
            if user[i] == "[":
                depth += 1
            elif user[i] == "]":
                depth -= 1
                if depth == 0:
                    return json.loads(user[brace : i + 1])
            i += 1
    except Exception:
        pass
    return []


def _hit_payload(user: str) -> dict:
    cands = _extract_candidates(user)
    target = cands[0] if cands else {"endpoint": "GET /api/invoices/{invoice_id}",
                                      "object_param": "invoice_id"}
    return {
        "is_vulnerable": True,
        "vulnerability_class": "BOLA / IDOR (CWE-639)",
        "target_endpoint": target.get("endpoint"),
        "object_param": target.get("object_param", "invoice_id"),
        "rationale": (
            "The endpoint authenticates the caller but the handler returns an "
            "object fetched by id with no check that it belongs to the caller. "
            "An authenticated user can read another tenant's object."
        ),
        "exploit_plan": {
            "actor": "user_A",
            "victim": "user_B",
            "steps": [
                "Authenticate as user_A.",
                "Request the victim's object id directly (e.g. /api/invoices/2).",
                "Observe the response contains user_B's data.",
            ],
        },
        "should_validate": True,
    }


def _miss_payload(user: str, rng: random.Random) -> dict:
    # Weak model: either declares it safe, or targets the wrong (guarded) path.
    if rng.random() < 0.5:
        return {
            "is_vulnerable": False,
            "rationale": (
                "Endpoint is authenticated and the query is parameterized; "
                "no obvious injection. Looks safe."
            ),
            "should_validate": False,
        }
    return {
        "is_vulnerable": True,
        "vulnerability_class": "SQL injection",
        "target_endpoint": "GET /api/me/invoices",
        "object_param": None,
        "rationale": "Suspected injection in the listing endpoint.",
        "exploit_plan": {"steps": ["probe for injection"]},
        "should_validate": True,
    }


def get_llm(prefer: str = "auto") -> BaseLLM:
    """Return a live Ollama client if reachable, else the deterministic stub."""
    if prefer == "stub":
        return StubLLM()
    if prefer == "ollama":
        return OllamaLLM()
    client = OllamaLLM()
    return client if client.available() else StubLLM()


def run_cost_usd(model: str, usage: Usage) -> float:
    tier_price = PRICE_PER_1K_USD.get(model)
    if tier_price is None:
        profile = STUB_PROFILES.get(model, DEFAULT_PROFILE)
        tier_price = PRICE_PER_1K_USD.get(profile[1], 0.0)
    return (usage.completion_tokens / 1000.0) * tier_price
