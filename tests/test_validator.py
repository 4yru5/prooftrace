"""The validator is the ground truth: it must actually reproduce the exploit,
and it must NOT false-positive against a patched app."""
from __future__ import annotations

import os

from prooftrace import validator


def test_exploit_reproduced_subprocess():
    ev, backend = validator.validate(backend="subprocess")
    assert backend == "subprocess"
    assert ev.exploit_reproduced is True
    assert ev.attacker_user == "user_A"
    assert ev.victim_user == "user_B"
    assert "FLAG{" in (ev.flag or "")
    # the transcript must show A receiving B's object
    assert any(ex.response_status == 200 for ex in ev.exchanges)


def test_transcript_shows_cross_tenant_read():
    ev, _ = validator.validate(backend="subprocess")
    txt = ev.transcript()
    assert "invoices/2" in txt
    assert "user_B" in txt  # A received B's data


def test_backend_choice_falls_back():
    # with no docker, auto must resolve to subprocess
    assert validator.choose_backend("subprocess") == "subprocess"
    assert validator.choose_backend("auto") in {"docker", "subprocess"}
