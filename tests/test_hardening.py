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


@pytest.mark.parametrize("name", [
    "app.go", "app.php", "app.rb", "app.rs", "main.c", "main.cpp",
    "App.java", "app.kt", "app.swift", "app.cs", "index.tsx", "app.scala",
    "svc.groovy", "handler.ex", "util.lua", "script.pl", "Dockerfile",
    "main.tf", "app.py", "index.js",
])
def test_common_languages_are_supported(name):
    assert fh.is_supported_file(name) is True


@pytest.mark.parametrize("name", ["image.png", "binary.exe", "photo.jpg", "blob.bin"])
def test_binary_files_still_rejected(name):
    assert fh.is_supported_file(name) is False


def test_zip_upload_clears_prior_context(tmp_path, monkeypatch):
    # A .zip is a whole project — uploading one must reset prior files so a
    # previous analysis can't contaminate its report.
    s = activate("default")
    s.workspace = str(tmp_path / "ws")
    os.makedirs(s.workspace, exist_ok=True)
    monkeypatch.setattr(fh, "add_document", lambda **kw: None)
    monkeypatch.setattr(fh, "run_all_scanners",
                        lambda _: {"findings": [], "tools_run": [], "tools_missing": []})
    memory["files"] = [{"name": "old.tf", "content": "x", "topic": "file", "project": "prev"}]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("proj/main.tf", 'region = "us-east-1"\n')
    fh.save_uploaded_files([{"name": "proj.zip",
                             "content": base64.b64encode(buf.getvalue()).decode()}])

    names = {f["name"] for f in memory["files"]}
    assert "old.tf" not in names                        # prior project cleared


def test_loose_file_upload_accumulates(tmp_path, monkeypatch):
    # Non-zip uploads must still accumulate (multi-file projects).
    s = activate("default")
    s.workspace = str(tmp_path / "ws2")
    os.makedirs(s.workspace, exist_ok=True)
    monkeypatch.setattr(fh, "add_document", lambda **kw: None)
    monkeypatch.setattr(fh, "run_all_scanners",
                        lambda _: {"findings": [], "tools_run": [], "tools_missing": []})
    memory["files"] = [{"name": "main.tf", "content": "x", "topic": "file", "project": "default"}]
    fh.save_uploaded_files([{"name": "Dockerfile",
                             "content": base64.b64encode(b"FROM ubuntu:latest\n").decode()}])
    names = {f["name"] for f in memory["files"]}
    assert "main.tf" in names and "Dockerfile" in names  # accumulated, not cleared


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


# =========================================================
# SCANNER CONTEXT ROLLUP (prompt token budgeting)
# =========================================================

def make_finding(sev, tool="checkov", rule="CKV_1", title="t", file="a.tf", line=1):
    return {"severity": sev, "tool": tool, "rule_id": rule,
            "title": title, "file": file, "line": line,
            "evidence": "", "guideline": None}


def test_small_scans_list_every_finding():
    from backend.prompt_engine import build_scanner_context
    memory["scan"] = {
        "findings": [make_finding("MEDIUM", rule=f"R{i}") for i in range(10)],
        "tools_run": ["checkov"], "tools_missing": [],
    }
    ctx = build_scanner_context()
    assert ctx.count("[MEDIUM]") == 10
    assert "×" not in ctx


def test_large_scans_roll_up_low_severities():
    from backend.prompt_engine import build_scanner_context
    findings = (
        [make_finding("CRITICAL", tool="gitleaks", rule="aws-key",
                      file=f"f{i}.tf", line=i) for i in range(4)]
        + [make_finding("MEDIUM", rule="CKV_K8S_20", title="no privesc",
                        file=f"m{i}.yaml", line=i) for i in range(147)]
        + [make_finding("LOW", rule="CKV_LOW", title="minor",
                        file=f"l{i}.yaml", line=i) for i in range(4)]
    )
    memory["scan"] = {"findings": findings,
                      "tools_run": ["checkov", "gitleaks"], "tools_missing": []}
    ctx = build_scanner_context()

    # All CRITICALs individually, MEDIUMs grouped to one line
    assert ctx.count("[CRITICAL]") == 4
    assert "checkov/CKV_K8S_20 ×147" in ctx
    assert "checkov/CKV_LOW ×4" in ctx
    assert "155 verified findings" in ctx
    # The whole section stays prompt-sized even for huge scans
    assert len(ctx) < 3000


# =========================================================
# BUG FIXES — client-IP trust, empty message, upload warnings
# =========================================================

def test_client_key_uses_rightmost_trusted_hop(monkeypatch):
    # One trusted proxy (default): the client-supplied leftmost value
    # is ignored, the appended real hop wins — spoofing is defeated
    monkeypatch.setattr(m, "TRUSTED_PROXY_HOPS", 1)

    class Req:
        def __init__(self, xff):
            self.headers = {"x-forwarded-for": xff} if xff else {}
            self.client = type("C", (), {"host": "10.9.0.1"})()

    # client tries to spoof 1.1.1.1; nginx appends the real peer 8.8.8.8
    assert m._client_key(Req("1.1.1.1, 8.8.8.8")) == "8.8.8.8"
    # rotating the spoofed value can't change the bucket
    assert m._client_key(Req("2.2.2.2, 8.8.8.8")) == "8.8.8.8"
    # single value (direct, no proxy appended) still works
    assert m._client_key(Req("8.8.8.8")) == "8.8.8.8"
    # no header → falls back to the socket peer
    assert m._client_key(Req(None)) == "10.9.0.1"


def test_empty_message_never_calls_llm(client, monkeypatch):
    called = {"llm": False}
    import backend.main as mod
    monkeypatch.setattr(mod, "ask_openai",
                        lambda *a, **k: called.__setitem__("llm", True) or "x")

    for msg in ["", "   ", "\n\t "]:
        r = client.post("/chat", json={"message": msg, "history": [], "files": []})
        assert r.status_code == 200
        assert "Type a question" in r.json()["response"]
    assert called["llm"] is False


def test_rejected_uploads_surfaced_in_response(client, monkeypatch):
    import backend.main as mod
    monkeypatch.setattr(
        mod, "save_uploaded_files",
        lambda files: [{"name": "huge.zip", "reason": "80 MB exceeds the 50 MB limit"}],
    )
    r = client.post("/chat", json={
        "message": "hi", "history": [],
        "files": [{"name": "huge.zip", "content": "x"}],
    })
    body = r.json()
    assert "Some uploads were skipped" in body["response"]
    assert "huge.zip" in body["response"]
    assert body["upload_warnings"][0]["name"] == "huge.zip"


# =========================================================
# ZIP MEMBER COUNT EXCLUDES IGNORED DIRS (issue #2)
# =========================================================

def test_zip_member_count_excludes_node_modules(tmp_path, monkeypatch):
    monkeypatch.setattr(fh, "MAX_ZIP_MEMBERS", 100)
    # 5000 node_modules files + 10 real files -> must NOT trip the guard
    entries = [(f"repo/node_modules/pkg{i}/index.js", b"x") for i in range(5000)]
    entries += [(f"repo/src/f{i}.tf", b'resource "a" "b" {}') for i in range(10)]
    z = make_zip(entries)
    fh.safe_extract(z, str(tmp_path))  # no raise
    # a real explosion of source files still trips it
    z2 = make_zip([(f"repo/src/f{i}.tf", b"x") for i in range(101)])
    with pytest.raises(ValueError, match="relevant entries"):
        fh.safe_extract(z2, str(tmp_path / "b"))


# =========================================================
# CONTENT-AWARE DEDUP (issue #8)
# =========================================================

def test_changed_file_replaces_stale_same_named(monkeypatch):
    monkeypatch.setattr(fh, "run_all_scanners", lambda _: {
        "findings": [], "tools_run": [], "tools_missing": []})
    monkeypatch.setattr(fh, "add_document", lambda **k: None)
    monkeypatch.setattr(fh, "remove_documents", lambda **k: None)

    fh.save_uploaded_files([{"name": "main.tf", "content": base64.b64encode(b'old = 1').decode()}])
    assert [f["content"] for f in memory["files"]] == ["old = 1"]
    # identical re-upload -> still one entry, unchanged
    fh.save_uploaded_files([{"name": "main.tf", "content": base64.b64encode(b'old = 1').decode()}])
    assert len([f for f in memory["files"] if f["name"] == "main.tf"]) == 1
    # changed content, same name -> replaced (recognised, not skipped)
    fh.save_uploaded_files([{"name": "main.tf", "content": base64.b64encode(b'new = 2').decode()}])
    tf = [f for f in memory["files"] if f["name"] == "main.tf"]
    assert len(tf) == 1 and tf[0]["content"] == "new = 2"


def test_ignored_dirs_removed_from_workspace_before_scan(tmp_path, monkeypatch):
    # A zip that ships .venv/.git must NOT leave them on disk for scanners
    import backend.file_handler as fhh
    from backend.session import activate
    monkeypatch.setattr(fhh, "add_document", lambda **k: None)
    sess = activate("zzz")
    sess.workspace = str(tmp_path / "ws")
    os.makedirs(sess.workspace)
    z = make_zip([
        ("proj/main.tf", b'resource "a" "b" {}'),
        ("proj/.venv/lib/pip/junk.py", b"import os"),
        ("proj/.git/config", b"[core]"),
        ("proj/node_modules/x/index.js", b"x"),
    ])
    import io as _io
    buf = _io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, d in [("proj/main.tf", b'resource "a" "b" {}'),
                     ("proj/.venv/lib/junk.py", b"import os"),
                     ("proj/.git/config", b"[core]")]:
            zf.writestr(n, d)
    buf.seek(0)
    zp = str(tmp_path / "u.zip")
    open(zp, "wb").write(buf.getvalue())
    fhh.ingest_zip(zp, project_name="proj")
    walked = []
    for root, _dirs, files in os.walk(sess.workspace):
        for f in files:
            walked.append(os.path.join(root, f))
    assert any("main.tf" in w for w in walked)
    assert not any(".venv" in w for w in walked), "scanner would still see .venv"
    assert not any(".git" in w for w in walked)
    from backend.session import destroy
    destroy("zzz")
