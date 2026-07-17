import numpy as np
import faiss

from backend.logging_setup import get_logger
from backend.openai_client import get_client
from backend.session import current

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
# RAG STORE — one per session
# In-memory only: lives and dies with the session, so one
# user's chunks can never leak into another's retrieval.
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
            query_lower = query.lower()

            # =============================================
            # SEMANTIC SEARCH
            # =============================================

            embedding = get_embedding(query)
            query_vector = np.array([embedding]).astype("float32")
            search_size = min(max(top_k * 8, 20), self.index.ntotal)
            distances, indices = self.index.search(query_vector, search_size)

            semantic_results = []
            for idx in indices[0]:
                if idx < len(self.documents):
                    doc = self.documents[idx]
                    if project_id and doc.get("project_id") != project_id:
                        continue
                    semantic_results.append(doc)

            # =============================================
            # KEYWORD BOOST SEARCH
            # =============================================

            keyword_results = []
            query_words = query_lower.split()

            for doc in self.documents:

                if project_id and doc.get("project_id") != project_id:
                    continue

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

                if score > 0:
                    boosted_doc = dict(doc)
                    boosted_doc["boost_score"] = score
                    keyword_results.append(boosted_doc)

            # =============================================
            # SORT + MERGE + DEDUPLICATE
            # =============================================

            keyword_results = sorted(
                keyword_results,
                key=lambda x: x.get("boost_score", 0),
                reverse=True
            )

            combined = keyword_results + semantic_results

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
    # session's store (used by tests and debugging sessions)
    if name == "index":
        return current().rag.index
    if name == "documents":
        return current().rag.documents
    raise AttributeError(f"module 'backend.rag' has no attribute '{name}'")
