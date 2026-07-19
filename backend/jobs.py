# =========================================================
# IN-PROCESS ASYNC JOBS
# A tiny job registry for long-running ingestion (repo
# download + scan) so /chat returns immediately instead of
# holding the request for ~40s. Matches the app's single-
# worker, in-process-state model — no queue, no broker.
#
# Jobs are scoped to the session that created them, expire
# after a TTL, and (like sessions) do not survive a restart.
# =========================================================

import time
import uuid

from backend.logging_setup import get_logger

logger = get_logger(__name__)

_JOBS: dict = {}
_JOB_TTL_SECONDS = 30 * 60
_MAX_JOBS = 500


def _sweep():
    cutoff = time.time() - _JOB_TTL_SECONDS
    stale = [jid for jid, j in _JOBS.items() if j["updated"] < cutoff]
    for jid in stale:
        _JOBS.pop(jid, None)
    # hard cap as a backstop against unbounded growth
    if len(_JOBS) > _MAX_JOBS:
        for jid in sorted(_JOBS, key=lambda k: _JOBS[k]["updated"])[:len(_JOBS) - _MAX_JOBS]:
            _JOBS.pop(jid, None)


def create_job(session_id: str, kind: str) -> str:
    _sweep()
    jid = uuid.uuid4().hex[:16]
    now = time.time()
    _JOBS[jid] = {
        "id": jid,
        "kind": kind,
        "session_id": session_id,
        "status": "running",   # running | done | error
        "phase": "starting",
        "result": None,
        "error": None,
        "created": now,
        "updated": now,
    }
    logger.info("job created id=%s kind=%s", jid, kind)
    return jid


def set_phase(jid: str, phase: str):
    j = _JOBS.get(jid)
    if j:
        j["phase"] = phase
        j["updated"] = time.time()


def finish_job(jid: str, result: dict):
    j = _JOBS.get(jid)
    if j:
        j.update(status="done", phase="done", result=result, updated=time.time())
        logger.info("job done id=%s", jid)


def fail_job(jid: str, error):
    j = _JOBS.get(jid)
    if j:
        j.update(status="error", error=str(error), updated=time.time())
        logger.warning("job failed id=%s error=%s", jid, error)


def get_job(jid: str, session_id: str = None):
    """Fetch a job. If session_id is given, only return the caller's own job."""
    j = _JOBS.get(jid)
    if j is None:
        return None
    if session_id is not None and j["session_id"] != session_id:
        return None
    return j


def public_view(job: dict) -> dict:
    """The job as the client should see it (no internal session id)."""
    return {
        "job_id": job["id"],
        "status": job["status"],
        "phase": job["phase"],
        "error": job["error"],
        "result": job["result"],
    }
