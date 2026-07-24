# Guards for the V2 contained fixes:
#  - .sarif is an accepted (text-readable) extension
#  - files over 20k chars are flagged truncated (no silent data loss)
#  - an all-rejected upload (e.g. an image) yields an honest "couldn't
#    read" note instead of a generic answer that reads like analysis
import base64
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import file_handler as fh
from backend.memory import memory
from backend.session import SESSIONS, activate, destroy


def _clean():
    for sid in list(SESSIONS):
        destroy(sid)
    activate("default")


def test_sarif_extension_supported():
    assert fh.is_supported_file("results.sarif") is True
    assert ".sarif" in fh.SUPPORTED_EXTENSIONS


def test_large_file_flagged_truncated():
    _clean()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as t:
        t.write("A" * 25000)
        path = t.name
    try:
        fh.ingest_single_file(filepath=path, original_filename="big.txt")
        entry = memory["files"][-1]
        assert entry["truncated"] is True
        assert len(entry["content"]) == 20000
    finally:
        os.remove(path)


def test_small_file_not_truncated():
    _clean()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as t:
        t.write("hello world")
        path = t.name
    try:
        fh.ingest_single_file(filepath=path, original_filename="small.txt")
        assert memory["files"][-1]["truncated"] is False
    finally:
        os.remove(path)


def test_unreadable_upload_gets_honest_note():
    _clean()
    import backend.main as m
    from fastapi.testclient import TestClient

    client = TestClient(m.app)
    png = base64.b64encode(bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A])).decode()
    # empty message avoids the LLM path; the honesty note is still prepended
    r = client.post("/chat", json={"message": "", "history": [],
                                    "files": [{"name": "diagram.png", "content": png}]},
                    headers={"X-Session-Id": "v2fix-img"})
    assert r.status_code == 200
    body = r.json()["response"].lower()
    assert "couldn't read" in body or "could not read" in body
    assert "not" in body and "analysis" in body  # sets expectation clearly
