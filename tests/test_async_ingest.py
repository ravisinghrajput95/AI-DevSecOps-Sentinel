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
