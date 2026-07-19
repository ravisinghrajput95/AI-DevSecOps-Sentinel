import io
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.github_ingest import (
    MAX_REPO_ZIP_BYTES,
    parse_github_url,
    strip_github_url,
)


# =========================================================
# URL PARSING
# =========================================================

@pytest.mark.parametrize("text,expected", [
    ("https://github.com/owner/repo", ("owner", "repo", None)),
    ("https://github.com/owner/repo/", ("owner", "repo", None)),
    ("https://github.com/owner/repo.git", ("owner", "repo", None)),
    ("http://www.github.com/owner/repo", ("owner", "repo", None)),
    ("https://github.com/owner/repo/tree/develop", ("owner", "repo", "develop")),
    ("https://github.com/my-org/my.repo-name", ("my-org", "my.repo-name", None)),
    ("scan https://github.com/owner/repo for secrets", ("owner", "repo", None)),
    ("check this: https://github.com/owner/repo.", ("owner", "repo", None)),
    ("what is kubernetes rbac", None),
    ("https://gitlab.com/owner/repo", None),
])
def test_parse_github_url(text, expected):
    assert parse_github_url(text) == expected


def test_strip_github_url_leaves_question():
    remaining = strip_github_url("scan https://github.com/o/r for secrets")
    assert "github.com" not in remaining
    assert "scan" in remaining and "for secrets" in remaining


# =========================================================
# INGESTION — download mocked, real ingest_zip path
# =========================================================

def _zipball_bytes(wrapper="owner-repo-abc1234"):
    """Build an in-memory GitHub-style zipball (single wrapper dir)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{wrapper}/main.tf", 'region = "us-east-1"\n')
        zf.writestr(f"{wrapper}/app/Dockerfile", "FROM ubuntu:latest\n")
    return buf.getvalue()


class _FakeResponse:
    def __init__(self, status_code=200, content=b""):
        self.status_code = status_code
        self._content = content

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size):
        for i in range(0, len(self._content), chunk_size):
            yield self._content[i:i + chunk_size]


@pytest.fixture
def clean_state(monkeypatch, tmp_path):
    """Fresh default session with tmp workspace, scanners stubbed."""
    import backend.file_handler as fh
    import backend.github_ingest as gi
    from backend.session import activate, destroy

    destroy("default")
    session = activate("default")
    session.workspace = str(tmp_path / "workspace")
    os.makedirs(session.workspace)
    monkeypatch.setattr(
        gi, "run_all_scanners",
        lambda _: {"findings": [], "tools_run": ["stub"], "tools_missing": []},
    )
    monkeypatch.setattr(fh, "add_document", lambda **kw: None)
    yield session.workspace
    destroy("default")
    activate("default")


def test_ingest_github_repo_clears_prior_context(clean_state, monkeypatch):
    # A repo is a self-contained project — a previously-analysed upload must
    # NOT bleed into its report (the cross-project contamination bug).
    import backend.github_ingest as gi
    from backend.memory import memory

    memory["files"] = [{"name": "vulnerable-samples/app.php", "content": "x",
                        "topic": "file", "project": "vulnerable-samples"}]
    monkeypatch.setattr(
        gi.requests, "get",
        lambda *a, **kw: _FakeResponse(content=_zipball_bytes()),
    )
    gi.ingest_github_repo("owner", "repo")

    names = {f["name"] for f in memory["files"]}
    assert "vulnerable-samples/app.php" not in names   # stale project cleared
    assert names == {"main.tf", "app/Dockerfile"}       # only the repo remains


def test_ingest_github_repo_flattens_wrapper(clean_state, monkeypatch):
    import backend.github_ingest as gi

    monkeypatch.setattr(
        gi.requests, "get",
        lambda *a, **kw: _FakeResponse(content=_zipball_bytes()),
    )
    result = gi.ingest_github_repo("owner", "repo")

    assert result == {"name": "owner/repo", "zip_name": "repo.zip", "files": 2}
    from backend.memory import memory
    names = {f["name"] for f in memory["files"]}
    # Wrapper dir flattened: paths do NOT start with owner-repo-abc1234/
    assert names == {"main.tf", "app/Dockerfile"}
    assert memory["scan"]["tools_run"] == ["stub"]
    # Workspace has the project dir with flattened contents
    assert os.path.isfile(os.path.join(clean_state, "repo", "main.tf"))


def test_ingest_github_repo_404(clean_state, monkeypatch):
    import backend.github_ingest as gi

    monkeypatch.setattr(
        gi.requests, "get", lambda *a, **kw: _FakeResponse(status_code=404)
    )
    with pytest.raises(ValueError, match="not found"):
        gi.ingest_github_repo("owner", "gone")


def test_ingest_github_repo_size_cap(clean_state, monkeypatch):
    import backend.github_ingest as gi

    big = _FakeResponse(content=b"x" * (MAX_REPO_ZIP_BYTES + 1))
    monkeypatch.setattr(gi.requests, "get", lambda *a, **kw: big)
    with pytest.raises(ValueError, match="50 MB"):
        gi.ingest_github_repo("owner", "huge")


# =========================================================
# CHAT FLOW — bare URL returns canned summary + findings
# =========================================================

def _poll_done(client, job_id, headers=None):
    import time
    for _ in range(40):
        s = client.get(f"/scan-status/{job_id}", headers=headers or {}).json()
        if s["status"] != "running":
            return s
        time.sleep(0.05)
    raise AssertionError("ingest job never finished")


def test_chat_with_bare_url_kicks_off_async_ingest(clean_state, monkeypatch):
    from fastapi.testclient import TestClient
    import backend.github_ingest as gi
    import backend.main as m

    monkeypatch.setattr(
        gi.requests, "get",
        lambda *a, **kw: _FakeResponse(content=_zipball_bytes()),
    )
    client = TestClient(m.app)
    kickoff = client.post("/chat", json={
        "message": "https://github.com/owner/repo",
        "history": [], "files": [],
    }).json()

    # Immediate response is a job handle, not the summary
    assert kickoff["status"] == "running"
    assert "Ingesting" in kickoff["response"]
    job_id = kickoff["job_id"]

    done = _poll_done(client, job_id)
    assert done["status"] == "done"
    result = done["result"]
    assert "Ingested" in result["response"]
    assert result["repo"]["zip_name"] == "repo.zip"
    assert "findings" in result and "scanners" in result


def test_chat_with_url_and_question_ingests_without_calling_llm(clean_state, monkeypatch):
    from unittest.mock import patch
    from fastapi.testclient import TestClient
    import backend.github_ingest as gi
    import backend.main as m

    monkeypatch.setattr(
        gi.requests, "get",
        lambda *a, **kw: _FakeResponse(content=_zipball_bytes()),
    )
    client = TestClient(m.app)
    # A URL with a question now also ingests asynchronously; the LLM is
    # NOT called during ingest — the user asks after the scan completes.
    with patch.object(m, "ask_openai", return_value="analysis here") as mock_llm:
        kickoff = client.post("/chat", json={
            "message": "scan https://github.com/owner/repo for misconfigurations",
            "history": [], "files": [],
        }).json()
        done = _poll_done(client, kickoff["job_id"])

    assert not mock_llm.called
    assert done["status"] == "done"
    assert done["result"]["repo"]["zip_name"] == "repo.zip"
