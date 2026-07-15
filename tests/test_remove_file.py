import base64
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable")


# =========================================================
# RAG REMOVAL — no API calls, vectors injected directly
# =========================================================

def test_remove_documents_rebuilds_index_without_reembedding():
    import backend.rag as rag

    rag.clear_rag()
    for i, source in enumerate(["a.tf", "a.tf", "b.tf"]):
        vec = [float(i)] * rag.EMBEDDING_DIMENSION
        rag.index.add(np.array([vec]).astype("float32"))
        rag.documents.append({
            "content": f"chunk{i}", "source": source,
            "project_id": "default", "topic": "file", "vector": vec,
        })

    rag.remove_documents(source="a.tf")
    assert len(rag.documents) == 1
    assert rag.documents[0]["source"] == "b.tf"
    assert rag.index.ntotal == 1

    rag.remove_documents(project_id="default")
    assert rag.documents == []
    assert rag.index.ntotal == 0


# =========================================================
# END-TO-END REMOVAL — real scanners, mirrors the UI flow
# =========================================================

@pytest.mark.skipif(
    __import__("shutil").which("gitleaks") is None
    or __import__("shutil").which("checkov") is None,
    reason="scanners not installed",
)
def test_remove_file_endpoint_drops_findings_and_rescans():
    from fastapi.testclient import TestClient
    import backend.main as m
    from backend.memory import memory

    client = TestClient(m.app)

    def b64(name):
        with open(os.path.join(FIXTURES, name), "rb") as f:
            return base64.b64encode(f.read()).decode()

    # Upload two files: main.tf carries the CRITICAL gitleaks secret
    client.post("/chat", json={"message": "ok", "history": [], "files": [
        {"name": "main.tf", "content": b64("main.tf")},
        {"name": "deployment.yaml", "content": b64("deployment.yaml")},
    ]})
    assert len(memory["files"]) == 2
    files_before = {f["file"] for f in memory["scan"]["findings"]}
    assert any("main.tf" in f for f in files_before)

    # Remove main.tf — the exact desync scenario from the UI
    r = client.post("/remove-file", json={"name": "main.tf"}).json()
    assert r["removed"] == 1
    assert r["files_in_memory"] == 1

    # Findings re-scanned across the FULL registry: no main.tf traces
    files_after = {f["file"] for f in r["findings"]}
    assert not any("main.tf" in f for f in files_after)
    assert not any(f["severity"] == "CRITICAL" for f in r["findings"])
    assert any("deployment.yaml" in f for f in files_after)

    # Workspace synced too
    assert "main.tf" not in os.listdir("workspace")

    # Removing the last file clears the scan entirely
    r = client.post("/remove-file", json={"name": "deployment.yaml"}).json()
    assert r["files_in_memory"] == 0
    assert r["findings"] == []
    assert memory["scan"] is None
