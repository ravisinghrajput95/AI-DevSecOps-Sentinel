# Guards for the two hardening fixes:
#  P1 — the SYSTEM_PROMPT carries an explicit refusal clause for
#       weaponizable payloads (fork bombs, mass-destructive DDL, malware).
#  P2 — scanner_status() is cached so /health never pays a per-call
#       filesystem/subprocess cost that could trip the readiness probe.

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.prompt_engine import SYSTEM_PROMPT
from backend import scanners


def test_system_prompt_has_operational_safety_section():
    p = SYSTEM_PROMPT.lower()
    assert "operational safety" in p
    # covers the two evaluated dual-use gaps + the clear-abuse classes
    assert "fork bomb" in p
    assert "truncating all tables" in p or "all tables or databases" in p
    assert "ransomware" in p and "reverse shell" in p


def test_system_prompt_still_allows_defensive_questions():
    # The refusal must be scoped to runnable weaponized artifacts, not topics —
    # otherwise legitimate defensive/educational questions get false-refused.
    p = SYSTEM_PROMPT.lower()
    assert "never refuse a genuine defensive" in p


def test_scanner_status_is_cached():
    # lru_cache returns the identical object on repeat calls, so /health is a
    # pure in-memory lookup after the first call.
    a = scanners.scanner_status()
    b = scanners.scanner_status()
    assert a is b
    assert set(a.keys()) == {s.TOOL for s in scanners.SCANNERS}
