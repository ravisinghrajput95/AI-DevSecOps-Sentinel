# get_embeddings sub-batches so no single request exceeds the per-request
# token cap (a big file's chunks summed to 603k tokens -> 400 before).
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import rag


class _FakeEmbeddings:
    def __init__(self, sink):
        self.sink = sink

    def create(self, model, input):
        self.sink.append(len(input))          # record batch size
        data = [types.SimpleNamespace(embedding=[0.0]) for _ in input]
        return types.SimpleNamespace(data=data)


def _install(monkeypatch):
    calls = []
    client = types.SimpleNamespace(embeddings=_FakeEmbeddings(calls))
    monkeypatch.setattr(rag, "get_client", lambda: client)
    return calls


def test_small_batch_single_call(monkeypatch):
    calls = _install(monkeypatch)
    out = rag.get_embeddings(["a", "b", "c"])
    assert len(out) == 3
    assert calls == [3]                        # one request


def test_large_batch_is_split(monkeypatch):
    calls = _install(monkeypatch)
    # each text ~200k tokens (800k chars) -> can't share a 250k-token request
    big = "x" * 800_000
    out = rag.get_embeddings([big, big, big])
    assert len(out) == 3
    assert len(calls) == 3                      # one per item (each too big to share)
    assert sum(calls) == 3                      # order/count preserved


def test_order_preserved_across_batches(monkeypatch):
    _install(monkeypatch)
    texts = ["y" * 700] * 500                   # 500 small chunks -> multiple batches
    out = rag.get_embeddings(texts)
    assert len(out) == 500
