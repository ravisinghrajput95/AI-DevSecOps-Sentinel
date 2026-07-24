# pgvector RAG backend. The DB-backed tests need a live Postgres
# (DATABASE_URL) and skip cleanly without one; they stub embeddings so
# they exercise storage + hybrid ranking without calling OpenAI. The
# backend-selection test always runs.

import os

import pytest

import backend.rag as rag
import backend.store as store
from backend.rag import add_document, clear_rag, remove_documents, search
from backend.session import Session, activate

DB = os.getenv("DATABASE_URL")
requires_db = pytest.mark.skipif(
    not DB, reason="no DATABASE_URL; pgvector tests skipped"
)


# =========================================================
# BACKEND SELECTION (no DB needed)
# =========================================================

def test_session_picks_backend_by_env(monkeypatch):
    from backend.rag import PgVectorStore, RagStore

    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert isinstance(Session("no-db").rag, RagStore)

    monkeypatch.setenv("DATABASE_URL", "postgresql://x")  # construction is lazy
    assert isinstance(Session("with-db").rag, PgVectorStore)


# =========================================================
# PGVECTOR STORE (needs a live Postgres)
# =========================================================

def _fake_vec(text):
    """Deterministic 1536-d vector so ANN ordering is stable without OpenAI."""
    v = [0.0] * store.EMBEDDING_DIMENSION
    h = abs(hash(text))
    v[h % store.EMBEDDING_DIMENSION] = 1.0
    v[(h // store.EMBEDDING_DIMENSION) % store.EMBEDDING_DIMENSION] = 0.5
    return v


@pytest.fixture
def pg(monkeypatch):
    monkeypatch.setattr(rag, "get_embeddings", lambda texts: [_fake_vec(t) for t in texts])
    monkeypatch.setattr(rag, "get_embedding", lambda text: _fake_vec(text))
    # Reset the pool so it binds to this test's DATABASE_URL, then build
    # the schema and truncate for a clean slate.
    monkeypatch.setattr(store, "_pg_pool", None)
    store.init_stores()
    activate("pgtest")
    yield


@requires_db
def test_add_and_search_returns_indexed_chunk(pg):
    add_document(content="FROM python:3.12\nRUN pip install flask",
                 source="Dockerfile", project="p", topic="docker")
    results = search("what base image does docker use", top_k=5)
    sources = [r["source"] for r in results]
    assert "Dockerfile" in sources


@requires_db
def test_keyword_boost_ranks_matching_file_first(pg):
    add_document(content="resource aws_s3_bucket demo {}", source="main.tf",
                 project="p", topic="terraform")
    add_document(content="FROM alpine\nUSER root", source="Dockerfile",
                 project="p", topic="docker")
    # "docker" query -> Dockerfile gets the filename boost and leads.
    results = search("docker security issues", top_k=5)
    assert results[0]["source"] == "Dockerfile"


@requires_db
def test_remove_by_source(pg):
    add_document(content="a", source="Dockerfile", project="p", topic="docker")
    add_document(content="b", source="main.tf", project="p", topic="terraform")
    remove_documents(source="Dockerfile")
    sources = [r["source"] for r in search("anything", top_k=10)]
    assert "Dockerfile" not in sources
    assert "main.tf" in sources


@requires_db
def test_clear_empties_the_session(pg):
    add_document(content="a", source="Dockerfile", project="p", topic="docker")
    clear_rag()
    assert search("anything", top_k=10) == []


@requires_db
def test_search_is_session_scoped(pg):
    activate("owner")
    add_document(content="secret", source="Dockerfile", project="p", topic="docker")

    activate("stranger")
    assert search("secret", top_k=10) == []  # no cross-session leakage

    activate("owner")
    assert [r["source"] for r in search("secret", top_k=10)] == ["Dockerfile"]
