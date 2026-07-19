import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _reload_llm(monkeypatch, **env):
    for k, v in env.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    import backend.llm as llm
    return importlib.reload(llm)


def test_max_tokens_defaults_to_4096(monkeypatch):
    llm = _reload_llm(monkeypatch, SENTINEL_LLM_MAX_TOKENS=None)
    assert llm.LLM_MAX_TOKENS == 4096


def test_max_tokens_respects_env(monkeypatch):
    llm = _reload_llm(monkeypatch, SENTINEL_LLM_MAX_TOKENS="16000")
    assert llm.LLM_MAX_TOKENS == 16000


def test_max_tokens_falls_back_on_garbage(monkeypatch):
    llm = _reload_llm(monkeypatch, SENTINEL_LLM_MAX_TOKENS="not-a-number")
    assert llm.LLM_MAX_TOKENS == 4096


def test_model_respects_env(monkeypatch):
    llm = _reload_llm(monkeypatch, SENTINEL_LLM_MODEL="gpt-5.6")
    assert llm.LLM_MODEL == "gpt-5.6"


def test_client_uses_base_url_when_set(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "https://gateway.example.com/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    import backend.openai_client as oc
    importlib.reload(oc)
    oc._client = None
    client = oc.get_client()
    assert "gateway.example.com" in str(client.base_url)


def test_client_defaults_to_openai_when_base_url_unset(monkeypatch):
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    import backend.openai_client as oc
    importlib.reload(oc)
    oc._client = None
    client = oc.get_client()
    assert "openai.com" in str(client.base_url)


def teardown_module(module):
    # Restore modules to a clean default so later tests see stock config.
    for env in ("SENTINEL_LLM_MAX_TOKENS", "SENTINEL_LLM_MODEL", "OPENAI_BASE_URL"):
        os.environ.pop(env, None)
    import backend.llm
    import backend.openai_client
    importlib.reload(backend.llm)
    importlib.reload(backend.openai_client)
    backend.openai_client._client = None
