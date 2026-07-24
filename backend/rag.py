import numpy as np
import faiss

from backend.logging_setup import get_logger
from backend.openai_client import get_client
from backend.session import current
from backend.store import pg_pool

logger = get_logger(__name__)

EMBEDDING_DIMENSION = 1536

# =========================================================
# CHUNKING
# =========================================================

def chunk_text(text, chunk_size=700, overlap=120):
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        if chunk.strip():
            chunks.append(chunk)
        start += chunk_size - overlap
    return chunks

# =========================================================
# EMBEDDINGS (stateless — shared by all sessions)
# =========================================================

def get_embedding(text):
    response = get_client().embeddings.create(
        model="text-embedding-3-small",
        input=text
    )
    return response.data[0].embedding


def get_embeddings(texts: list) -> list:
    """Batched embeddings — one API call for all chunks of a file."""
    response = get_client().embeddings.create(
        model="text-embedding-3-small",
        input=texts
    )
    return [item.embedding for item in response.data]

# =========================================================
# HYBRID RANKING — shared by both backends so retrieval
# results are identical whether chunks live in FAISS or
# pgvector. Semantic (ANN) hits are merged with keyword-
# boosted hits, then deduplicated.
# =========================================================

def _keyword_score(doc, query_lower, query_words) -> int:
    filename = doc["source"].lower()
    content_lower = doc["content"].lower()
    score = 0

    # Exact file match
    if filename in query_lower:
        score += 15

    # Partial file match
    for word in query_words:
        if word in filename:
            score += 4

    # Content match
    for word in query_words:
        if len(word) > 3 and word in content_lower:
            score += 1

    # Special boosts
    if "docker" in query_lower and "dockerfile" in filename:
        score += 10

    if "kubernetes" in query_lower and any(
        k in filename for k in ["deployment", "service", "ingress"]
    ):
        score += 8

    if "terraform" in query_lower and filename.endswith(".tf"):
        score += 10

    if "jenkins" in query_lower and "jenkinsfile" in filename:
        score += 10

    if "github actions" in query_lower and ".github" in filename:
        score += 10

    if "sql injection" in query_lower and any(
        x in content_lower
        for x in ["statement.execute", "querystring", "select *"]
    ):
        score += 10

    return score


def _rank(query, all_docs, semantic_docs, top_k):
    """
    Merge keyword-boosted matches (scored over `all_docs`, the full
    in-scope set) with `semantic_docs` (the ANN hits), dedupe, and
    return the top_k. Callers pre-filter both lists by project.
    """
    query_lower = query.lower()
    query_words = query_lower.split()

    keyword_results = []
    for doc in all_docs:
        score = _keyword_score(doc, query_lower, query_words)
        if score > 0:
            boosted = dict(doc)
            boosted["boost_score"] = score
            keyword_results.append(boosted)

    keyword_results.sort(key=lambda x: x.get("boost_score", 0), reverse=True)
    combined = keyword_results + semantic_docs

    seen = set()
    unique_results = []
    for item in combined:
        key = (item["source"], item["content"][:150])
        if key not in seen:
            seen.add(key)
            unique_results.append(item)

    if logger.isEnabledFor(10):  # DEBUG
        logger.debug(
            "retrieval top_k=%d results=%s",
            top_k,
            [
                f"{r['source']}(boost={r.get('boost_score', 0)})"
                for r in unique_results[:top_k]
            ],
        )

    return unique_results[:top_k]

# =========================================================
# IN-MEMORY RAG STORE (default) — one per session.
# Lives and dies with the session, so one user's chunks
# can never leak into another's retrieval.
# =========================================================

class RagStore:
    def __init__(self):
        self.index = faiss.IndexFlatL2(EMBEDDING_DIMENSION)
        self.documents = []

    def add(self, text, source, project_id, topic):
        chunks = chunk_text(text)
        if not chunks:
            return

        # One batched API call per file instead of one per chunk —
        # repo-scale ingestion goes from hundreds of round-trips to
        # one per file.
        try:
            embeddings = get_embeddings(chunks)
        except Exception:
            logger.exception("embedding failed for source=%s", source)
            return

        for chunk, embedding in zip(chunks, embeddings):
            vector = np.array([embedding]).astype("float32")
            self.index.add(vector)
            self.documents.append({
                "content": chunk,
                "source": source,
                "project_id": project_id,
                "topic": topic,
                # kept so removals can rebuild the index without
                # paying for re-embedding; never leaves the process
                "vector": embedding,
            })

    def search(self, query, top_k=5, project_id=None):
        if self.index.ntotal == 0:
            return []

        try:
            embedding = get_embedding(query)
            query_vector = np.array([embedding]).astype("float32")
            search_size = min(max(top_k * 8, 20), self.index.ntotal)
            distances, indices = self.index.search(query_vector, search_size)

            semantic_docs = []
            for idx in indices[0]:
                if idx < len(self.documents):
                    doc = self.documents[idx]
                    if project_id and doc.get("project_id") != project_id:
                        continue
                    semantic_docs.append(doc)

            all_docs = [
                d for d in self.documents
                if not (project_id and d.get("project_id") != project_id)
            ]

            return _rank(query, all_docs, semantic_docs, top_k)

        except Exception:
            logger.exception("RAG search failed")
            return []

    def remove(self, source=None, project_id=None):
        """
        Drop all chunks belonging to a source file or a project and
        rebuild the index from the stored vectors (no re-embedding).
        """
        def keep(doc):
            if project_id is not None and doc.get("project_id") == project_id:
                return False
            if source is not None and doc.get("source") == source:
                return False
            return True

        before = len(self.documents)
        self.documents = [d for d in self.documents if keep(d)]

        self.index = faiss.IndexFlatL2(EMBEDDING_DIMENSION)
        vectors = [d["vector"] for d in self.documents if d.get("vector")]
        if vectors:
            self.index.add(np.array(vectors).astype("float32"))

        logger.info("RAG removed %d chunks (source=%s project=%s)",
                    before - len(self.documents), source, project_id)

    def clear(self):
        self.documents = []
        self.index = faiss.IndexFlatL2(EMBEDDING_DIMENSION)
        logger.info("RAG cleared")

# =========================================================
# PGVECTOR RAG STORE — used when DATABASE_URL is set.
# Chunks live in the shared `rag_chunks` table, scoped to the
# active session id so retrieval stays per-user isolated
# exactly like the in-memory store. Same public interface.
# =========================================================

class PgVectorStore:
    @staticmethod
    def _row(r):
        return {"source": r[0], "content": r[1], "project_id": r[2], "topic": r[3]}

    def add(self, text, source, project_id, topic):
        chunks = chunk_text(text)
        if not chunks:
            return

        try:
            embeddings = get_embeddings(chunks)
        except Exception:
            logger.exception("embedding failed for source=%s", source)
            return

        session_id = current().id
        rows = [
            (session_id, project_id, source, topic, chunk,
             np.array(embedding, dtype="float32"))
            for chunk, embedding in zip(chunks, embeddings)
        ]
        with pg_pool().connection() as conn, conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO rag_chunks "
                "(session_id, project_id, source, topic, content, embedding) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                rows,
            )

    def search(self, query, top_k=5, project_id=None):
        session_id = current().id

        # Embed the query BEFORE borrowing a connection so the pool
        # isn't held during the OpenAI round-trip.
        try:
            embedding = get_embedding(query)
        except Exception:
            logger.exception("RAG query embedding failed")
            return []
        query_vector = np.array(embedding, dtype="float32")

        try:
            where = "WHERE session_id = %s"
            params = [session_id]
            if project_id:
                where += " AND project_id = %s"
                params.append(project_id)

            with pg_pool().connection() as conn, conn.cursor() as cur:
                cur.execute(f"SELECT count(*) FROM rag_chunks {where}", params)
                ntotal = cur.fetchone()[0]
                if ntotal == 0:
                    return []
                search_size = min(max(top_k * 8, 20), ntotal)

                # Semantic (ANN) hits — L2 distance to match FAISS.
                cur.execute(
                    "SELECT source, content, project_id, topic "
                    f"FROM rag_chunks {where} "
                    "ORDER BY embedding <-> %s LIMIT %s",
                    params + [query_vector, search_size],
                )
                semantic_docs = [self._row(r) for r in cur.fetchall()]

                # Full in-scope set for keyword boosting (mirrors the
                # in-memory store iterating every document).
                cur.execute(
                    f"SELECT source, content, project_id, topic FROM rag_chunks {where}",
                    params,
                )
                all_docs = [self._row(r) for r in cur.fetchall()]
        except Exception:
            logger.exception("RAG search failed")
            return []

        return _rank(query, all_docs, semantic_docs, top_k)

    def remove(self, source=None, project_id=None):
        clauses = ["session_id = %s"]
        params = [current().id]
        if project_id is not None:
            clauses.append("project_id = %s")
            params.append(project_id)
        if source is not None:
            clauses.append("source = %s")
            params.append(source)

        with pg_pool().connection() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM rag_chunks WHERE " + " AND ".join(clauses), params
            )
            removed = cur.rowcount
        logger.info("RAG removed %d chunks (source=%s project=%s)",
                    removed, source, project_id)

    def clear(self):
        with pg_pool().connection() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM rag_chunks WHERE session_id = %s", (current().id,))
        logger.info("RAG cleared")

# =========================================================
# MODULE-LEVEL API — thin wrappers over the ACTIVE session's
# store, so importers and tests keep their existing calls.
# =========================================================

def add_document(
    text=None,
    source="unknown",
    project_id="default",
    topic="general",
    content=None,
    project=None
):
    actual_text = content if content is not None else text
    actual_project = project if project is not None else project_id

    if not actual_text:
        logger.warning("add_document: no content for source=%s, skipping", source)
        return

    current().rag.add(actual_text, source, actual_project, topic)


def search(query, top_k=5, project_id=None):
    return current().rag.search(query, top_k=top_k, project_id=project_id)


def remove_documents(source=None, project_id=None):
    current().rag.remove(source=source, project_id=project_id)


def clear_rag():
    current().rag.clear()


def build_context(results):
    if not results:
        return ""

    context = []
    for item in results:
        source = item.get("source", "unknown")
        project_id = item.get("project_id", "default")
        content = item.get("content", "")
        context.append(
            f"PROJECT: {project_id}\nFILE: {source}\nCONTENT:\n{content}"
        )

    return "\n\n---\n\n".join(context)


def __getattr__(name):
    # Back-compat: `rag.index` / `rag.documents` resolve to the active
    # session's store (used by tests and debugging sessions). Only the
    # in-memory RagStore exposes these; under the pgvector backend they
    # raise AttributeError, which is expected (those callers are FAISS-mode).
    if name == "index":
        return current().rag.index
    if name == "documents":
        return current().rag.documents
    raise AttributeError(f"module 'backend.rag' has no attribute '{name}'")
