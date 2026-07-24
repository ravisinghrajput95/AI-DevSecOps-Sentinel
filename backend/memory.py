# =========================================================
# SESSION-SCOPED MEMORY
# `memory` keeps its historical dict-style interface
# (memory["files"], memory.get("scan"), ...) but delegates
# to the ACTIVE session's state, so every existing call
# site works unchanged while users stay isolated.
#
# Two backends, chosen at runtime by REDIS_URL (see
# backend/store.py):
#   - Redis (REDIS_URL set): each key is a JSON field of the
#     hash `sentinel:session:<sid>:memory`, so session memory
#     is shared and survives a worker restart.
#   - in-process dict (default): the original per-Session dict.
#
# IMPORTANT for the Redis backend: reads return a FRESH copy
# from Redis, so in-place mutation of a returned value does
# NOT persist. Call sites must read-modify-write instead of
# `memory["files"].append(...)` — see backend/file_handler.py.
# =========================================================

from backend.session import SESSION_TTL_SECONDS, _fresh_memory, current
from backend.store import KEY_PREFIX, dumps, loads, redis_client


def _key() -> str:
    return f"{KEY_PREFIX}:session:{current().id}:memory"


class _SessionMemory:
    def __getitem__(self, key):
        r = redis_client()
        if r is None:
            return current().memory[key]
        raw = r.hget(_key(), key)
        # Miss => the same default the in-process dict is seeded with
        # (_fresh_memory pre-populates every key), so callers never
        # hit a KeyError on a fresh session.
        if raw is None:
            return _fresh_memory()[key]
        return loads(raw)

    def __setitem__(self, key, value):
        r = redis_client()
        if r is None:
            current().memory[key] = value
            return
        k = _key()
        r.hset(k, key, dumps(value))
        r.expire(k, SESSION_TTL_SECONDS)

    def __contains__(self, key):
        r = redis_client()
        if r is None:
            return key in current().memory
        # Fresh keys are conceptually always present (the dict backend
        # seeds them), plus anything explicitly written.
        return key in _fresh_memory() or bool(r.hexists(_key(), key))

    def get(self, key, default=None):
        r = redis_client()
        if r is None:
            return current().memory.get(key, default)
        raw = r.hget(_key(), key)
        if raw is None:
            return _fresh_memory().get(key, default)
        return loads(raw)


memory = _SessionMemory()
