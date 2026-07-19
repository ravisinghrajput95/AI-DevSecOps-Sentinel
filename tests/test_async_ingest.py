import os
import sys
import time
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import backend.main as m
from backend import jobs
from backend.session import SESSIONS, activate, destroy


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    jobs._JOBS.clear()
    for sid in list(SESSIONS):
        destroy(sid)
    activate("default")
    yield
    jobs._JOBS.clear()
    for sid in list(SESSIONS):
        destroy(sid)
    activate("default")


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    return TestClient(m.app)


# ---- job registry ----

def test_job_lifecycle_and_session_scope():
    jid = jobs.create_job("sess-a", "github-ingest")
    assert jobs.get_job(jid, "sess-a")["status"] == "running"
    # a different session cannot see it
    assert jobs.get_job(jid, "sess-b") is None

    jobs.set_phase(jid, "scanning")
    assert jobs.get_job(jid, "sess-a")["phase"] == "scanning"

    jobs.finish_job(jid, {"response": "done", "findings": []})
    j = jobs.get_job(jid, "sess-a")
    assert j["status"] == "done"
    assert jobs.public_view(j)["result"]["response"] == "done"
    assert "session_id" not in jobs.public_view(j)  # not leaked


def test_job_failure():
    jid = jobs.create_job("s", "x")
    jobs.fail_job(jid, "boom")
    j = jobs.get_job(jid, "s")
    assert j["status"] == "error" and "boom" in j["error"]


# ---- endpoint flow ----

def _drive_to_done(client, jid, headers):
    for _ in range(30):
        s = client.get(f"/scan-status/{jid}", headers=headers).json()
        if s["status"] != "running":
            return s
        time.sleep(0.05)
    raise AssertionError("job never finished")


def test_chat_github_url_kicks_off_job_and_completes(client):
    fake = {"name": "o/r", "files": 3, "zip_name": "r.zip"}
    with patch("backend.main.ingest_github_repo", return_value=fake), \
         patch("backend.main._github_summary",
               return_value={"response": "📦 Ingested o/r", "findings": [],
                             "scanners": {"run": [], "missing": []}, "repo": fake}):
        r = client.post("/chat", json={"message": "https://github.com/o/r"})
        body = r.json()
        assert r.status_code == 200
        assert body["status"] == "running"
        jid = body["job_id"]
        done = _drive_to_done(client, jid, {})
        assert done["status"] == "done"
        assert "Ingested" in done["result"]["response"]


def test_zip_plus_url_prioritises_upload_and_skips_url(client):
    # Both an attachment and a repo URL in one message: the upload wins,
    # the URL is skipped (no async job started), and the reply says so.
    import base64
    content = base64.b64encode(b"FROM ubuntu:latest\nUSER root\n").decode()
    with patch("backend.main.build_prompt", return_value="P"), \
         patch("backend.main.ask_openai", return_value="Analysis done."):
        r = client.post("/chat", json={
            "message": "scan https://github.com/o/r",
            "files": [{"name": "Dockerfile", "content": content}],
        })
    body = r.json()
    assert r.status_code == 200
    assert "job_id" not in body          # URL ingest was NOT started
    assert "was skipped" in body["response"]
    assert "o/r" in body["response"]
    assert "Analysis done." in body["response"]


def test_greeting_with_files_identifies_as_ai(client):
    # "hi" with a file in context must still identify as AI (not just
    # "Hey! I still have your files…").
    import base64
    m.memory["files"] = []
    content = base64.b64encode(b"FROM ubuntu:latest\n").decode()
    r = client.post("/chat", json={
        "message": "hi", "files": [{"name": "Dockerfile", "content": content}]
    }).json()
    assert "AI DevSecOps Sentinel" in r["response"]
    assert "in context" in r["response"].lower()


def test_affirmative_after_offer_runs_audit(client):
    # "yes please" right after the assistant offered an audit menu must run
    # the analysis (findings surfaced), not re-prompt with the same menu.
    import base64
    m.memory["files"] = []  # start clean
    content = base64.b64encode(b"FROM ubuntu:latest\nUSER root\n").decode()
    with patch("backend.main.build_prompt", return_value="P"), \
         patch("backend.main.ask_openai", return_value="Full audit complete."):
        # upload a file first so it's in context
        client.post("/chat", json={"message": "hi", "files": [{"name": "Dockerfile", "content": content}]})
        offer_history = [["hi", "What would you like to explore next?\n- Security audit"]]
        r = client.post("/chat", json={"message": "yes please", "history": offer_history}).json()
    assert "Full audit complete." in r["response"]
    assert "What would you like to dig into next" not in r["response"]


def test_affirmative_without_offer_shows_menu(client):
    # A bare "yes" with NO prior offer (e.g. after a findings result) must
    # NOT spuriously re-run analysis — it re-prompts with the menu.
    import base64
    m.memory["files"] = []
    content = base64.b64encode(b"FROM ubuntu:latest\n").decode()
    client.post("/chat", json={"message": "hi", "files": [{"name": "Dockerfile", "content": content}]})
    r = client.post("/chat", json={
        "message": "yes please",
        "history": [["audit", "REPOSITORY SUMMARY: 1 finding"]],
    }).json()
    assert "What would you like to dig into next" in r["response"]


def test_url_alone_still_starts_ingest_job(client):
    # No attachment → a bare URL must still kick off the repo ingest job.
    fake = {"name": "o/r", "files": 2}
    with patch("backend.main.ingest_github_repo", return_value=fake), \
         patch("backend.main._github_summary", return_value={"response": "ok"}):
        body = client.post(
            "/chat", json={"message": "https://github.com/o/r"}
        ).json()
        assert body.get("status") == "running" and "job_id" in body


def test_failed_ingest_reports_error(client):
    with patch("backend.main.ingest_github_repo", side_effect=ValueError("not found")):
        jid = client.post(
            "/chat", json={"message": "https://github.com/o/missing"}
        ).json()["job_id"]
        done = _drive_to_done(client, jid, {})
        assert done["status"] == "error"
        assert "not found" in done["error"]


def test_unknown_job_is_404(client):
    assert client.get("/scan-status/deadbeef").status_code == 404


def test_job_is_session_isolated_over_http(client):
    fake = {"name": "o/r", "files": 1}
    with patch("backend.main.ingest_github_repo", return_value=fake), \
         patch("backend.main._github_summary", return_value={"response": "ok"}):
        jid = client.post("/chat", headers={"X-Session-Id": "alice"},
                          json={"message": "https://github.com/o/r"}).json()["job_id"]
        # Bob cannot read Alice's job
        assert client.get(f"/scan-status/{jid}",
                          headers={"X-Session-Id": "bob"}).status_code == 404
        # Alice can
        assert client.get(f"/scan-status/{jid}",
                          headers={"X-Session-Id": "alice"}).status_code == 200
