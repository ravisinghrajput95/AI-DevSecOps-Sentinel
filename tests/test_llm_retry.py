# On an OpenAI rate-limit (429), ask_openai retries once with a much
# smaller completion reservation so a large-repo question still gets
# answered instead of erroring. Non-rate-limit errors do NOT retry.
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from backend import llm


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(llm.time, "sleep", lambda *a, **k: None)


def _resp(text):
    msg = types.SimpleNamespace(content=text)
    return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)], usage=None)


class _FakeClient:
    def __init__(self, behavior):
        self.behavior = behavior          # callable(max_tokens) -> resp or raises
        self.calls = []
        self.chat = types.SimpleNamespace(
            completions=types.SimpleNamespace(create=self._create))

    def _create(self, model, messages, temperature, max_tokens):
        self.calls.append(max_tokens)
        return self.behavior(max_tokens)


def _install(monkeypatch, behavior):
    client = _FakeClient(behavior)
    monkeypatch.setattr(llm, "get_client", lambda: client)
    return client


def test_success_no_retry(monkeypatch):
    client = _install(monkeypatch, lambda mt: _resp("full answer"))
    assert llm.ask_openai("hi") == "full answer"
    assert client.calls == [llm.LLM_MAX_TOKENS]        # one call, full budget


def test_rate_limit_retries_with_smaller_reservation(monkeypatch):
    def behavior(mt):
        if mt == llm.LLM_MAX_TOKENS:
            raise RuntimeError("Error code: 429 - rate_limit_exceeded (TPM)")
        return _resp("recovered answer")
    client = _install(monkeypatch, behavior)
    out = llm.ask_openai("analyze this big repo")
    assert out == "recovered answer"
    assert client.calls[0] == llm.LLM_MAX_TOKENS
    assert client.calls[1] < llm.LLM_MAX_TOKENS         # retried smaller


def test_non_rate_limit_does_not_retry(monkeypatch):
    client = _install(monkeypatch, lambda mt: (_ for _ in ()).throw(RuntimeError("boom")))
    out = llm.ask_openai("hi")
    assert "error occurred" in out.lower()
    assert len(client.calls) == 1                       # no retry on generic error


def test_persistent_rate_limit_returns_message(monkeypatch):
    client = _install(monkeypatch, lambda mt: (_ for _ in ()).throw(RuntimeError("429 rate_limit")))
    out = llm.ask_openai("hi")
    assert "rate limit" in out.lower()
    assert len(client.calls) == 2                       # tried, then retried, then gave message
