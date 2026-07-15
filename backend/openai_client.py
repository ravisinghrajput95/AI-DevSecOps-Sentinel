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
        _client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    return _client
