import base64
import io
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import backend.file_handler as fh
import backend.main as m
from backend.memory import memory
from backend.session import SESSIONS, activate, destroy


@pytest.fixture(autouse=True)
def clean_sessions():
    for sid in list(SESSIONS):
        destroy(sid)
    activate("default")
    yield
    for sid in list(SESSIONS):
        destroy(sid)
    activate("default")


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    return TestClient(m.app)


# =========================================================
# API KEY AUTH
# =========================================================

def test_open_when_no_api_key_configured(client, monkeypatch):
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    r = client.post("/chat", json={"message": "hello", "history": [], "files": []})
    assert r.status_code == 200


def test_api_key_required_when_configured(client, monkeypatch):
    monkeypatch.setenv("SENTINEL_API_KEY", "sentinel-test-key")

    # Missing key
    r = client.post("/chat", json={"message": "hello", "history": [], "files": []})
    assert r.status_code == 401

    # Wrong key
    r = client.post(
        "/chat",
        headers={"X-API-Key": "wrong"},
        json={"message": "hello", "history": [], "files": []},
    )
    assert r.status_code == 401

    # Correct key
    r = client.post(
        "/chat",
        headers={"X-API-Key": "sentinel-test-key"},
        json={"message": "hello", "history": [], "files": []},
    )
    assert r.status_code == 200

    # /health stays open for probes
    assert client.get("/health").status_code == 200


# =========================================================
# RATE LIMIT — /chat
# =========================================================

def test_chat_rate_limited_per_client(client, monkeypatch):
    monkeypatch.setattr(m, "RATE_LIMIT_PER_MINUTE", 2)
    monkeypatch.setattr(m.time, "time", lambda: 1_000_000.0)
    m._rate_buckets.clear()

    payload = {"message": "hello", "history": [], "files": []}
    assert client.post("/chat", json=payload).status_code == 200
    assert client.post("/chat", json=payload).status_code == 200
    r = client.post("/chat", json=payload)
    assert r.status_code == 429
    assert "Rate limit" in r.json()["detail"]

    # A different client (per X-Forwarded-For) has its own bucket
    r = client.post("/chat", headers={"X-Forwarded-For": "10.0.0.9"}, json=payload)
    assert r.status_code == 200

    # Next minute window resets the count
    monkeypatch.setattr(m.time, "time", lambda: 1_000_060.0)
    assert client.post("/chat", json=payload).status_code == 200


def test_rate_limit_zero_disables(client, monkeypatch):
    monkeypatch.setattr(m, "RATE_LIMIT_PER_MINUTE", 0)
    m._rate_buckets.clear()
    payload = {"message": "hello", "history": [], "files": []}
    for _ in range(5):
        assert client.post("/chat", json=payload).status_code == 200


# =========================================================
# REQUEST BODY SIZE LIMIT
# =========================================================

def test_oversized_request_rejected_with_413(client, monkeypatch):
    monkeypatch.setattr(m, "MAX_REQUEST_BYTES", 1024)
    r = client.post("/chat", json={
        "message": "x" * 5000, "history": [], "files": [],
    })
    assert r.status_code == 413
    assert "limit" in r.json()["detail"]


def test_normal_request_passes_size_limit(client, monkeypatch):
    monkeypatch.setattr(m, "MAX_REQUEST_BYTES", 1024)
    r = client.post("/chat", json={"message": "hi", "history": [], "files": []})
    assert r.status_code == 200


# =========================================================
# ZIP GUARDS (safe_extract)
# =========================================================

def make_zip(entries):
    """entries: list of (name, bytes)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    buf.seek(0)
    return zipfile.ZipFile(buf)


def test_zip_member_count_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(fh, "MAX_ZIP_MEMBERS", 3)
    z = make_zip([(f"f{i}.txt", b"x") for i in range(4)])
    with pytest.raises(ValueError, match="entries"):
        fh.safe_extract(z, str(tmp_path))


def test_zip_uncompressed_size_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(fh, "MAX_ZIP_UNCOMPRESSED_BYTES", 1024)
    # 1 MB of zeros compresses to almost nothing — classic bomb shape
    z = make_zip([("zeros.txt", b"\0" * (1024 * 1024))])
    with pytest.raises(ValueError, match="expands to"):
        fh.safe_extract(z, str(tmp_path))


def test_zip_slip_still_blocked(tmp_path):
    z = make_zip([("../escape.txt", b"pwned")])
    with pytest.raises(ValueError, match="Zip Slip"):
        fh.safe_extract(z, str(tmp_path))


def test_zip_within_limits_extracts(tmp_path):
    z = make_zip([("ok.txt", b"fine"), ("sub/also.txt", b"fine")])
    fh.safe_extract(z, str(tmp_path))
    assert (tmp_path / "ok.txt").read_text() == "fine"


# =========================================================
# PER-FILE UPLOAD CAP
# =========================================================

def test_oversized_single_file_skipped(monkeypatch):
    monkeypatch.setattr(fh, "MAX_FILE_BYTES", 100)
    big = base64.b64encode(b"A" * 200).decode()
    fh.save_uploaded_files([{"name": "big.tf", "content": big}])
    assert memory["files"] == []


def test_small_file_still_ingested(monkeypatch):
    monkeypatch.setattr(fh, "MAX_FILE_BYTES", 10_000)
    # Keep the unit test offline: no scanner subprocesses, no
    # embeddings API call from RAG indexing.
    monkeypatch.setattr(fh, "run_all_scanners", lambda _: {
        "findings": [], "tools_run": [], "tools_missing": [],
    })
    monkeypatch.setattr(fh, "add_document", lambda **kwargs: None)
    small = base64.b64encode(b'resource "aws_s3_bucket" "b" {}').decode()
    fh.save_uploaded_files([{"name": "main.tf", "content": small}])
    assert [f["name"] for f in memory["files"]] == ["main.tf"]
