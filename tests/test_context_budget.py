# Repo-sized scans shrink the raw file-context budget so a big-repo
# question stays under the account's TPM budget (the terragoat 869-finding
# case 429'd even after the reduced-reservation retry).
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import backend.prompt_engine as pe
from backend.memory import memory
from backend.session import SESSIONS, activate, destroy


def _reset():
    for sid in list(SESSIONS):
        destroy(sid)
    activate("default")
    pe._file_context_cache = {"key": None, "value": None}


def _big_file():
    memory["files"] = [{"name": "big.txt", "content": "X" * 30000,
                        "topic": "file", "project": "default"}]


def test_large_scan_shrinks_file_context():
    _reset()
    _big_file()
    memory["scan"] = {"findings": [{"severity": "HIGH", "file": "a", "line": 1}
                                   for _ in range(60)]}   # > rollup threshold
    ctx = pe.build_full_file_context()
    assert len(ctx) <= 6000      # shrunk toward the 4k large-repo budget


def test_small_scan_keeps_full_context():
    _reset()
    _big_file()
    memory["scan"] = {"findings": [{"severity": "HIGH", "file": "a", "line": 1}
                                   for _ in range(3)]}    # few findings
    ctx = pe.build_full_file_context()
    assert len(ctx) > 13000      # full 40k budget retained for small analyses
