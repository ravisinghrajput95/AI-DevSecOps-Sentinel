# =========================================================
# LAZY OPENAI CLIENT
# The client is created on first use, not at import time,
# so the app boots without an OPENAI_API_KEY. Scanner-based
# features work keyless; LLM/embedding calls fail gracefully
# inside their existing try/except blocks.
# =========================================================

import os

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

_client = None


def get_client() -> OpenAI:
    global _client
    if _client is None:
        # OPENAI_BASE_URL lets us point at any OpenAI-compatible endpoint
        # (an OpenAI-compat gateway like LiteLLM/OpenRouter, an Anthropic
        # or Bedrock proxy, a self-hosted model) without a code change —
        # so switching the model tomorrow is pure config. Unset => the
        # real OpenAI API, exactly as before.
        base_url = os.getenv("OPENAI_BASE_URL") or None
        _client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"), base_url=base_url)
    return _client
