import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import backend.main as m
from backend import metrics
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


def test_metrics_endpoint_serves_prometheus_format(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    assert "# HELP sentinel_http_requests_total" in r.text
    assert "sentinel_active_sessions" in r.text


def test_metrics_is_auth_exempt(client, monkeypatch):
    # Even with an API key required, /metrics stays open (in-cluster scrape)
    monkeypatch.setenv("SENTINEL_API_KEY", "secret-key")
    assert client.get("/metrics").status_code == 200
    # ...while /chat is gated
    assert client.post("/chat", json={"message": "hi"}).status_code == 401


def test_http_requests_counter_increments(client):
    def total():
        return client.get("/metrics").text

    client.post("/chat", json={"message": "hi", "history": [], "files": []})
    body = total()
    # a labeled sample for POST /chat must now be present
    assert 'sentinel_http_requests_total{method="POST",path="/chat"' in body


def test_active_sessions_gauge_reflects_registry(client):
    client.post("/chat", headers={"X-Session-Id": "sess-a"}, json={"message": "hi"})
    client.post("/chat", headers={"X-Session-Id": "sess-b"}, json={"message": "hi"})
    body = client.get("/metrics").text
    # gauge is set at scrape time to len(SESSIONS); at least our 2 + default
    line = next(l for l in body.splitlines()
                if l.startswith("sentinel_active_sessions "))
    assert float(line.split()[1]) >= 2


def test_llm_and_scan_metric_families_registered(client):
    body = client.get("/metrics").text
    for fam in [
        "sentinel_llm_request_duration_seconds",
        "sentinel_llm_tokens_total",
        "sentinel_llm_errors_total",
        "sentinel_scan_duration_seconds",
        "sentinel_scan_findings_total",
        "sentinel_uploads_rejected_total",
        "sentinel_files_ingested_total",
    ]:
        assert fam in body, f"missing metric family {fam}"


def test_upload_rejection_label_is_bounded():
    # The reject reason is bucketed to a fixed category, not free text
    import backend.file_handler as fh
    before = metrics.UPLOADS_REJECTED.labels(reason="too_large")._value.get()
    fh.save_uploaded_files([{"name": "x.tf", "content": ""}])  # empty -> "empty"
    empty_after = metrics.UPLOADS_REJECTED.labels(reason="empty")._value.get()
    assert empty_after >= 1
    # unchanged bucket stays put (proves bucketing, not per-message labels)
    assert metrics.UPLOADS_REJECTED.labels(reason="too_large")._value.get() == before
