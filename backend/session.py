# =========================================================
# SESSION REGISTRY
# Every browser tab gets an isolated session — files, scan
# cache, RAG index, secret registry, and workspace dir —
# keyed by the X-Session-Id header (client-generated UUID).
# A ContextVar carries the active session id through each
# request so module-level accessors (memory proxy, rag
# wrappers, redaction registry) resolve the right state
# without threading a session object through every call.
#
# Requests without a header use the literal "default"
# session, which keeps tests, scripts, and evals working.
# =========================================================

import os
import re
import shutil
import time
from contextvars import ContextVar

SESSION_TTL_SECONDS = 2 * 60 * 60
WORKSPACE_ROOT = "workspace"

# Session ids become directory names — restrict strictly so a
# hostile header can never traverse paths.
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")


def _fresh_memory() -> dict:
    return {
        "files": [],
        "last_response": None,
        "last_topic": "",
        "last_files": [],
        "general_mode": False,
        "rag_cache_key": None,
        "rag_results": [],
        "scan": None,
    }


class Session:
    def __init__(self, session_id: str):
        self.id = session_id
        self.memory = _fresh_memory()
        self._rag = None
        self.secrets = set()
        self.workspace = os.path.join(WORKSPACE_ROOT, session_id)
        self.last_used = time.time()

    @property
    def rag(self):
        # Created on first use, imported lazily: scanner-only usage
        # (the eval benchmark, minimal CI environments) must work
        # without the RAG stack (faiss/numpy/openai) installed —
        # and rag.py itself imports session for current().
        if self._rag is None:
            from backend.rag import RagStore
            self._rag = RagStore()
        return self._rag


SESSIONS: dict = {}
_current_id: ContextVar = ContextVar("session_id", default="default")


def sanitize_session_id(raw) -> str:
    if raw and _SESSION_ID_RE.match(raw):
        return raw
    return "default"


def current() -> Session:
    """The active request's session, created lazily."""
    sid = _current_id.get()
    session = SESSIONS.get(sid)
    if session is None:
        session = SESSIONS[sid] = Session(sid)
        print(f"Session created: {sid} ({len(SESSIONS)} active)")
    session.last_used = time.time()
    return session


def activate(session_id) -> Session:
    """Bind a session to the current request context."""
    _current_id.set(sanitize_session_id(session_id))
    sweep_expired()
    return current()


def destroy(session_id: str):
    session = SESSIONS.pop(session_id, None)
    if session:
        shutil.rmtree(session.workspace, ignore_errors=True)


def sweep_expired():
    cutoff = time.time() - SESSION_TTL_SECONDS
    for sid in [s for s, sess in SESSIONS.items() if sess.last_used < cutoff]:
        print(f"Session expired: {sid}")
        destroy(sid)


# =========================================================
# STARTUP — sessions are in-memory, so every workspace dir
# on disk is stale after a restart. Wipe the whole root.
# =========================================================

if os.path.isdir(WORKSPACE_ROOT):
    shutil.rmtree(WORKSPACE_ROOT, ignore_errors=True)
os.makedirs(WORKSPACE_ROOT, exist_ok=True)
