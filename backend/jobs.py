# =========================================================
# ASYNC JOB REGISTRY
# A tiny registry for long-running ingestion (repo download +
# scan) so /chat returns immediately instead of holding the
# request for ~40s. Jobs are scoped to the session that
# created them and expire after a TTL.
#
# Two backends, chosen at runtime by REDIS_URL (see
# backend/store.py):
#   - Redis (REDIS_URL set): job state is shared and survives
#     a worker restart. Redis key TTL handles expiry.
#   - in-process dict (default): the original single-worker
#     model — no queue, no broker; lost on restart.
#
# NOTE: even on Redis the ingest runs on an in-process thread,
# so a job left "running" when the worker dies is orphaned and
# ages out via TTL — durable execution needs a real queue
# (deferred; see docs/DESIGN-DECISIONS.md).
# =========================================================

import time
import uuid

from backend.logging_setup import get_logger
from backend.store import KEY_PREFIX, dumps, loads, redis_client

logger = get_logger(__name__)

_JOBS: dict = {}
_JOB_TTL_SECONDS = 30 * 60
_MAX_JOBS = 500


def _key(jid: str) -> str:
    return f"{KEY_PREFIX}:job:{jid}"


# =========================================================
# IN-PROCESS HOUSEKEEPING (dict backend only; Redis uses TTL)
# =========================================================

def _sweep():
    cutoff = time.time() - _JOB_TTL_SECONDS
    stale = [jid for jid, j in _JOBS.items() if j["updated"] < cutoff]
    for jid in stale:
        _JOBS.pop(jid, None)
    # hard cap as a backstop against unbounded growth
    if len(_JOBS) > _MAX_JOBS:
        for jid in sorted(_JOBS, key=lambda k: _JOBS[k]["updated"])[:len(_JOBS) - _MAX_JOBS]:
            _JOBS.pop(jid, None)


# =========================================================
# REDIS SERIALIZATION
# =========================================================

def _to_hash(job: dict) -> dict:
    return {
        "id": job["id"],
        "kind": job["kind"],
        "session_id": job["session_id"],
        "status": job["status"],
        "phase": job["phase"],
        "error": dumps(job["error"]),
        "result": dumps(job["result"]),
        "created": repr(job["created"]),
        "updated": repr(job["updated"]),
    }


def _from_hash(h: dict) -> dict:
    return {
        "id": h["id"],
        "kind": h["kind"],
        "session_id": h["session_id"],
        "status": h["status"],
        "phase": h["phase"],
        "error": loads(h.get("error")),
        "result": loads(h.get("result")),
        "created": float(h["created"]),
        "updated": float(h["updated"]),
    }


def _redis_store(r, job: dict):
    key = _key(job["id"])
    r.hset(key, mapping=_to_hash(job))
    r.expire(key, _JOB_TTL_SECONDS)


def _redis_patch(r, jid: str, **fields):
    """Update fields of an existing job and refresh its TTL."""
    key = _key(jid)
    if not r.exists(key):
        return None
    fields["updated"] = repr(time.time())
    if "error" in fields:
        fields["error"] = dumps(fields["error"])
    if "result" in fields:
        fields["result"] = dumps(fields["result"])
    r.hset(key, mapping=fields)
    r.expire(key, _JOB_TTL_SECONDS)
    return True


# =========================================================
# PUBLIC API
# =========================================================

def create_job(session_id: str, kind: str) -> str:
    jid = uuid.uuid4().hex[:16]
    now = time.time()
    job = {
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
    r = redis_client()
    if r is not None:
        _redis_store(r, job)
    else:
        _sweep()
        _JOBS[jid] = job
    logger.info("job created id=%s kind=%s", jid, kind)
    return jid


def set_phase(jid: str, phase: str):
    r = redis_client()
    if r is not None:
        _redis_patch(r, jid, phase=phase)
        return
    j = _JOBS.get(jid)
    if j:
        j["phase"] = phase
        j["updated"] = time.time()


def finish_job(jid: str, result: dict):
    r = redis_client()
    if r is not None:
        _redis_patch(r, jid, status="done", phase="done", result=result)
        logger.info("job done id=%s", jid)
        return
    j = _JOBS.get(jid)
    if j:
        j.update(status="done", phase="done", result=result, updated=time.time())
        logger.info("job done id=%s", jid)


def fail_job(jid: str, error):
    r = redis_client()
    if r is not None:
        _redis_patch(r, jid, status="error", error=str(error))
        logger.warning("job failed id=%s error=%s", jid, error)
        return
    j = _JOBS.get(jid)
    if j:
        j.update(status="error", error=str(error), updated=time.time())
        logger.warning("job failed id=%s error=%s", jid, error)


def get_job(jid: str, session_id: str = None):
    """Fetch a job. If session_id is given, only return the caller's own job."""
    r = redis_client()
    if r is not None:
        h = r.hgetall(_key(jid))
        j = _from_hash(h) if h else None
    else:
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
