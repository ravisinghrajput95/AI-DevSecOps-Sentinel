# =========================================================
# EXTERNAL STATE BACKENDS — Redis + pgvector
#
# The app's session state (job registry, session memory, RAG
# index) is in-process by default. Setting the matching env
# var switches a backend to a shared external store so state
# survives a worker restart and stops being pod-local:
#
#   REDIS_URL     -> jobs + session memory move to Redis
#   DATABASE_URL  -> RAG moves to pgvector
#
# Both are OPTIONAL. Unset (the default for tests, evals, and
# keyless/scanner-only runs) keeps the exact in-process
# behavior, and the redis/psycopg/pgvector packages are only
# imported when the corresponding var is set — so environments
# that never install them still boot. Mirrors the lazy-client
# pattern in backend/openai_client.py.
# =========================================================

import json
import os
import threading

from backend.logging_setup import get_logger

logger = get_logger(__name__)

# All keys this app writes to Redis share this prefix so the
# startup reset (and any future multi-tenant Redis) can target
# them precisely.
KEY_PREFIX = "sentinel"

# text-embedding-3-small — must match backend.rag.EMBEDDING_DIMENSION.
EMBEDDING_DIMENSION = 1536

_redis = None
_redis_lock = threading.Lock()

_pg_pool = None
_pg_lock = threading.Lock()


# =========================================================
# BACKEND SELECTION
# =========================================================

def redis_enabled() -> bool:
    return bool(os.getenv("REDIS_URL"))


def pg_enabled() -> bool:
    return bool(os.getenv("DATABASE_URL"))


# =========================================================
# CLIENTS (lazy, thread-safe singletons)
# =========================================================

def redis_client():
    """Shared Redis client, or None when REDIS_URL is unset."""
    global _redis
    if not redis_enabled():
        return None
    if _redis is not None:
        return _redis
    with _redis_lock:
        if _redis is None:
            import redis  # lazy: only when configured
            _redis = redis.Redis.from_url(
                os.environ["REDIS_URL"],
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
            )
            logger.info("redis backend enabled")
    return _redis


def pg_pool():
    """
    Shared psycopg connection pool, or None when DATABASE_URL is unset.

    Connections register the pgvector type adapter, so init_stores()
    MUST have created the `vector` extension before the pool opens its
    first connection (startup always calls init_stores() first).
    """
    global _pg_pool
    if not pg_enabled():
        return None
    if _pg_pool is not None:
        return _pg_pool
    with _pg_lock:
        if _pg_pool is None:
            from psycopg_pool import ConnectionPool
            from pgvector.psycopg import register_vector

            _pg_pool = ConnectionPool(
                os.environ["DATABASE_URL"],
                min_size=1,
                max_size=int(os.getenv("SENTINEL_PG_POOL_MAX", "8")),
                kwargs={"autocommit": True},
                configure=register_vector,
                open=True,
            )
            logger.info("pgvector backend enabled")
    return _pg_pool


# =========================================================
# SCHEMA + STARTUP RESET
# =========================================================

_DDL = (
    "CREATE EXTENSION IF NOT EXISTS vector",
    f"""CREATE TABLE IF NOT EXISTS rag_chunks (
        id         bigserial PRIMARY KEY,
        session_id text  NOT NULL,
        project_id text  NOT NULL DEFAULT 'default',
        source     text  NOT NULL DEFAULT 'unknown',
        topic      text  NOT NULL DEFAULT 'general',
        content    text  NOT NULL,
        embedding  vector({EMBEDDING_DIMENSION}) NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS rag_chunks_scope_idx "
    "ON rag_chunks (session_id, project_id)",
    # HNSW builds incrementally (no training data needed, unlike ivfflat)
    # and uses L2 distance to match the old FAISS IndexFlatL2.
    "CREATE INDEX IF NOT EXISTS rag_chunks_embedding_idx "
    "ON rag_chunks USING hnsw (embedding vector_l2_ops)",
)


def init_stores():
    """
    Idempotent startup hook (called from the FastAPI lifespan).

    - pgvector: create the extension/table/indexes, then TRUNCATE.
    - Redis: drop stale session keys but KEEP job keys.

    Both resets match today's behavior: backend/session.py wipes the
    local workspace dir on startup, so sessions are effectively fresh
    after a restart — we mirror that for the externalized state so it
    can never dangle against a wiped workspace. This is the single
    thing to remove when moving to multi-replica + workspace
    re-materialization (see the HARD CONSTRAINT note in the backend
    Deployment).
    """
    if pg_enabled():
        _init_pg()
    r = redis_client()
    if r is not None:
        _reset_sessions(r)


def _init_pg():
    import psycopg  # lazy
    # A plain connection (not the pool) so the `vector` extension exists
    # before pg_pool() ever tries to register its type adapter.
    with psycopg.connect(os.environ["DATABASE_URL"], autocommit=True) as conn:
        with conn.cursor() as cur:
            for stmt in _DDL:
                cur.execute(stmt)
            cur.execute("TRUNCATE rag_chunks")
    logger.info("pgvector startup init: schema ready, rag_chunks truncated")


def _reset_sessions(r):
    keys = list(r.scan_iter(match=f"{KEY_PREFIX}:session:*", count=500))
    if keys:
        r.delete(*keys)
    logger.info("redis startup reset: cleared %d session keys "
                "(job keys preserved)", len(keys))


# =========================================================
# JSON HELPERS — every value stored in a Redis hash field is
# JSON so lists/dicts survive the round-trip.
# =========================================================

def dumps(value) -> str:
    return json.dumps(value, separators=(",", ":"))


def loads(raw):
    return json.loads(raw) if raw is not None else None
