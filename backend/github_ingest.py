# =========================================================
# GITHUB REPO INGESTION
# Paste a GitHub URL in chat — the repo is downloaded as a
# zipball (no git binary, no token for public repos) and fed
# through the existing zip ingestion path: workspace, RAG,
# and the full scanner registry.
# =========================================================

import os
import re
import shutil
import tempfile

import requests

from backend.file_handler import clear_workspace, ingest_zip, workspace_dir
from backend.memory import memory
from backend.rag import clear_rag
from backend.redaction import clear_secrets
from backend.scanners import run_all_scanners

# Streaming download cap — protects against huge repos
MAX_REPO_ZIP_BYTES = 50 * 1024 * 1024

_GITHUB_URL_RE = re.compile(
    r"https?://(?:www\.)?github\.com/"
    r"(?P<owner>[A-Za-z0-9_.\-]+)/"
    r"(?P<repo>[A-Za-z0-9_.\-]+)"
    r"(?:/tree/(?P<branch>[^\s?#]+))?"
    r"(?:[/?#][^\s]*)?"
    r"(?=[\s,;:!)\]]|$)"
)


def parse_github_url(text: str):
    """
    Find a GitHub repo URL anywhere in text. Returns
    (owner, repo, branch_or_None) or None. A /tree/<ref> suffix is
    treated as the branch to download.
    """
    match = _GITHUB_URL_RE.search(text or "")
    if not match:
        return None
    owner = match.group("owner")
    # Repo names may contain dots, so the regex matches greedily and
    # sentence punctuation / .git suffixes are trimmed here instead.
    repo = match.group("repo").rstrip(".")
    if repo.endswith(".git"):
        repo = repo[:-4]
    branch = match.group("branch")
    if branch:
        branch = branch.rstrip("/")
    return owner, repo, branch


def strip_github_url(text: str) -> str:
    """Remove the matched URL so the rest of the message can be routed."""
    return _GITHUB_URL_RE.sub("", text or "").strip()


def _download_zipball(owner: str, repo: str, branch=None) -> bytes:
    if branch:
        url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"
    else:
        # Resolves the default branch and redirects to codeload
        url = f"https://api.github.com/repos/{owner}/{repo}/zipball"

    response = requests.get(
        url,
        stream=True,
        timeout=30,
        headers={"User-Agent": "AI-DevSecOps-Sentinel"},
    )
    if response.status_code == 404:
        raise ValueError(
            f"'{owner}/{repo}'"
            + (f" (branch '{branch}')" if branch else "")
            + " was not found on GitHub — check the URL, and note that"
            " private repositories are not supported."
        )
    response.raise_for_status()

    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=1 << 16):
        total += len(chunk)
        if total > MAX_REPO_ZIP_BYTES:
            raise ValueError(
                "Repository archive exceeds the 50 MB ingestion limit — "
                "try a smaller repository or upload selected files instead."
            )
        chunks.append(chunk)
    return b"".join(chunks)


def ingest_github_repo(owner: str, repo: str, branch=None) -> dict:
    """
    Download and ingest a public GitHub repo. Returns a summary dict;
    raises ValueError with a user-facing message on failure.
    """
    try:
        data = _download_zipball(owner, repo, branch)
    except requests.RequestException as e:
        raise ValueError(f"could not download the repository ({e})")

    # A repo is a complete, self-contained project — reset the session first
    # so files/findings from a previously analysed upload or repo can't
    # contaminate this report (cross-project bleed). Done only after the
    # download succeeds, so a failed fetch never wipes existing context.
    memory["files"] = []
    memory["last_topic"] = ""
    memory["last_files"] = []
    memory["rag_cache_key"] = None
    memory["rag_results"] = []
    memory["scan"] = None
    clear_workspace()
    clear_rag()
    clear_secrets()

    tmpdir = tempfile.mkdtemp()
    try:
        # The zip filename becomes the project name in ingest_zip
        zip_path = os.path.join(tmpdir, f"{repo}.zip")
        with open(zip_path, "wb") as f:
            f.write(data)
        indexed_files = ingest_zip(zip_path)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    memory["scan"] = run_all_scanners(workspace_dir())

    return {
        "name": f"{owner}/{repo}" + (f"@{branch}" if branch else ""),
        "zip_name": f"{repo}.zip",
        "files": len(indexed_files),
    }
