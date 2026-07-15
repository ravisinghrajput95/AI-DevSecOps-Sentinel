import numpy as np
import faiss

from backend.openai_client import get_client

EMBEDDING_DIMENSION = 1536

# =========================================================
# IN-MEMORY INDEX
# Lives and dies with the process — same lifetime as
# memory["files"], so stale chunks from earlier sessions
# can never leak back into retrieval via an on-disk index.
# =========================================================

index = faiss.IndexFlatL2(EMBEDDING_DIMENSION)
documents = []

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
# EMBEDDINGS
# =========================================================

def get_embedding(text):
    response = get_client().embeddings.create(
        model="text-embedding-3-small",
        input=text
    )
    return response.data[0].embedding

# =========================================================
# ADD DOCUMENT
# Supports both calling conventions:
#   - add_document(text, source, project_id)        old style
#   - add_document(content=, source=, project=)     file_handler.py style
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
        print("add_document: no content provided, skipping.")
        return

    chunks = chunk_text(actual_text)

    for chunk in chunks:
        try:
            embedding = get_embedding(chunk)
            vector = np.array([embedding]).astype("float32")
            index.add(vector)
            documents.append({
                "content": chunk,
                "source": source,
                "project_id": actual_project,
                "topic": topic,
                # kept so removals can rebuild the index without
                # paying for re-embedding; never leaves the process
                "vector": embedding,
            })
        except Exception as e:
            print("Embedding error:", e)

# =========================================================
# PROJECT FILTER
# =========================================================

def filter_by_project(results, project_id):
    if not project_id:
        return results
    return [r for r in results if r.get("project_id") == project_id]

# =========================================================
# SEARCH
# =========================================================

def search(query, top_k=5, project_id=None):
    if index.ntotal == 0:
        return []

    try:
        query_lower = query.lower()

        # =================================================
        # SEMANTIC SEARCH
        # =================================================

        embedding = get_embedding(query)
        query_vector = np.array([embedding]).astype("float32")
        search_size = min(max(top_k * 8, 20), index.ntotal)
        distances, indices = index.search(query_vector, search_size)

        semantic_results = []
        for idx in indices[0]:
            if idx < len(documents):
                doc = documents[idx]
                if project_id and doc.get("project_id") != project_id:
                    continue
                semantic_results.append(doc)

        # =================================================
        # KEYWORD BOOST SEARCH
        # =================================================

        keyword_results = []
        query_words = query_lower.split()

        for doc in documents:

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

        # =================================================
        # SORT + MERGE + DEDUPLICATE
        # =================================================

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

        # =================================================
        # DEBUG
        # =================================================

        print("\n=== RETRIEVAL RESULTS ===")
        for r in unique_results[:top_k]:
            print(
                f"PROJECT: {r.get('project_id')} | "
                f"FILE: {r['source']} | "
                f"BOOST: {r.get('boost_score', 0)}"
            )
        print("==========================\n")

        return unique_results[:top_k]

    except Exception as e:
        print("Search error:", e)
        return []

# =========================================================
# CONTEXT BUILDER
# =========================================================

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

# =========================================================
# REMOVE DOCUMENTS
# =========================================================

def remove_documents(source=None, project_id=None):
    """
    Drop all chunks belonging to a source file or a project and
    rebuild the index from the stored vectors (no re-embedding).
    """
    global documents, index

    def keep(doc):
        if project_id is not None and doc.get("project_id") == project_id:
            return False
        if source is not None and doc.get("source") == source:
            return False
        return True

    before = len(documents)
    documents = [d for d in documents if keep(d)]

    index = faiss.IndexFlatL2(EMBEDDING_DIMENSION)
    vectors = [d["vector"] for d in documents if d.get("vector")]
    if vectors:
        index.add(np.array(vectors).astype("float32"))

    print(f"RAG: removed {before - len(documents)} chunks "
          f"(source={source}, project={project_id})")

# =========================================================
# CLEAR ALL
# =========================================================

def clear_rag():
    global documents, index
    documents = []
    index = faiss.IndexFlatL2(EMBEDDING_DIMENSION)
    print("RAG cleared")