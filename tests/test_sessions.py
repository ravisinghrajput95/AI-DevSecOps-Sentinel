import base64
import os
import shutil
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.session import (
    SESSION_TTL_SECONDS,
    SESSIONS,
    activate,
    current,
    destroy,
    sanitize_session_id,
    sweep_expired,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable")

SCANNERS_PRESENT = (
    shutil.which("gitleaks") is not None and shutil.which("checkov") is not None
)


@pytest.fixture(autouse=True)
def clean_sessions():
    for sid in list(SESSIONS):
        destroy(sid)
    activate("default")
    yield
    for sid in list(SESSIONS):
        destroy(sid)
    activate("default")


# =========================================================
# SESSION PRIMITIVES
# =========================================================

def test_sanitize_rejects_path_traversal():
    assert sanitize_session_id("../evil") == "default"
    assert sanitize_session_id("a/b") == "default"
    assert sanitize_session_id("") == "default"
    assert sanitize_session_id(None) == "default"
    assert sanitize_session_id("x" * 65) == "default"
    assert sanitize_session_id("abc-DEF-123") == "abc-DEF-123"


def test_sessions_are_isolated_objects():
    a = activate("session-a")
    a.memory["files"].append({"name": "a.tf"})
    a.secrets.add("secret-a")

    b = activate("session-b")
    assert b.memory["files"] == []
    assert b.secrets == set()
    assert b.workspace != a.workspace

    back = activate("session-a")
    assert back is a
    assert back.memory["files"][0]["name"] == "a.tf"


def test_memory_proxy_follows_active_session():
    from backend.memory import memory

    activate("session-a")
    memory["last_topic"] = "topic-a"
    activate("session-b")
    assert memory["last_topic"] == ""
    activate("session-a")
    assert memory["last_topic"] == "topic-a"


def test_redaction_registry_is_per_session():
    from backend.redaction import remember_secret, scrub_secrets

    activate("session-a")
    remember_secret("OnlySessionAKnows42")
    assert "OnlySessionAKnows42" not in scrub_secrets("x OnlySessionAKnows42 x")

    activate("session-b")
    # B never saw that secret — no exact-match scrub (and no pattern hit)
    assert "OnlySessionAKnows42" in scrub_secrets("x OnlySessionAKnows42 x")


def test_ttl_eviction_removes_state_and_workspace():
    session = activate("short-lived")
    os.makedirs(session.workspace, exist_ok=True)
    assert "short-lived" in SESSIONS

    session.last_used = time.time() - SESSION_TTL_SECONDS - 1
    sweep_expired()

    assert "short-lived" not in SESSIONS
    assert not os.path.exists(session.workspace)


# =========================================================
# END-TO-END ISOLATION VIA THE API
# =========================================================

@pytest.mark.skipif(not SCANNERS_PRESENT, reason="scanners not installed")
def test_two_sessions_see_only_their_own_files():
    from fastapi.testclient import TestClient
    import backend.main as m

    client = TestClient(m.app)

    def b64(name):
        with open(os.path.join(FIXTURES, name), "rb") as f:
            return base64.b64encode(f.read()).decode()

    ALICE = {"X-Session-Id": "alice-tab"}
    BOB = {"X-Session-Id": "bob-tab"}

    client.post("/chat", headers=ALICE, json={
        "message": "ok", "history": [],
        "files": [{"name": "main.tf", "content": b64("main.tf")}],
    })
    client.post("/chat", headers=BOB, json={
        "message": "ok", "history": [],
        "files": [{"name": "deployment.yaml", "content": b64("deployment.yaml")}],
    })

    # Each session's health reports only its own files
    assert client.get("/health", headers=ALICE).json()["files_in_memory"] == 1
    assert client.get("/health", headers=BOB).json()["files_in_memory"] == 1

    # Scanner findings never cross sessions
    alice_files = {f["file"] for f in SESSIONS["alice-tab"].memory["scan"]["findings"]}
    bob_files = {f["file"] for f in SESSIONS["bob-tab"].memory["scan"]["findings"]}
    assert any("main.tf" in f for f in alice_files)
    assert not any("deployment.yaml" in f for f in alice_files)
    assert any("deployment.yaml" in f for f in bob_files)
    assert not any("main.tf" in f for f in bob_files)

    # Workspaces are separate directories
    assert os.listdir(SESSIONS["alice-tab"].workspace) == ["main.tf"]
    assert os.listdir(SESSIONS["bob-tab"].workspace) == ["deployment.yaml"]

    # Clear in Alice's session leaves Bob untouched
    r = client.post("/chat", headers=ALICE, json={
        "message": "clear context", "history": [], "files": [],
    }).json()
    assert "cleared" in r["response"].lower()
    assert client.get("/health", headers=ALICE).json()["files_in_memory"] == 0
    assert client.get("/health", headers=BOB).json()["files_in_memory"] == 1


@pytest.mark.skipif(not SCANNERS_PRESENT, reason="scanners not installed")
def test_headerless_requests_use_default_session():
    from fastapi.testclient import TestClient
    import backend.main as m

    client = TestClient(m.app)
    r = client.get("/health").json()
    assert "files_in_memory" in r
    assert "default" in SESSIONS
