import os
import time

from backend import metrics
from backend.logging_setup import get_logger
from backend.openai_client import get_client
from backend.prompt_engine import SYSTEM_PROMPT

logger = get_logger(__name__)

LLM_MODEL = os.environ.get("SENTINEL_LLM_MODEL", "gpt-4o")

# Completion cap. Heavier models writing long reports can hit the default,
# so it's tunable per deployment without a code change. Falls back to 4096
# (the previous hard-coded value) if unset or unparseable.
try:
    LLM_MAX_TOKENS = int(os.environ.get("SENTINEL_LLM_MAX_TOKENS", "4096"))
except ValueError:
    LLM_MAX_TOKENS = 4096

# Old analyses in history can be huge (full repo reports) — cap each
# item so history (12 messages max) can't push the request over the
# model's TPM limit: 12 x 2500 chars ~ 7.5k tokens worst case
MAX_HISTORY_ITEM_CHARS = 2500


def ask_openai(prompt: str, history: list = []) -> str:

    # =========================================================
    # BUILD MESSAGES
    # =========================================================

    messages = [
        {
            "role": "system",
            "content": SYSTEM_PROMPT
        }
    ]

    # =========================================================
    # INJECT CONVERSATION HISTORY
    # =========================================================

    for item in history[-6:]:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            messages.append({
                "role": "user",
                "content": str(item[0])[:MAX_HISTORY_ITEM_CHARS]
            })
            messages.append({
                "role": "assistant",
                "content": str(item[1])[:MAX_HISTORY_ITEM_CHARS]
            })

    # =========================================================
    # INJECT CURRENT PROMPT
    # =========================================================

    messages.append({
        "role": "user",
        "content": prompt
    })

    # =========================================================
    # CALL OPENAI
    # =========================================================

    start = time.time()
    try:
        response = get_client().chat.completions.create(
            model=LLM_MODEL,
            messages=messages,
            temperature=0.2,
            max_tokens=LLM_MAX_TOKENS
        )
        metrics.LLM_LATENCY.observe(time.time() - start)
        usage = getattr(response, "usage", None)
        if usage:
            metrics.LLM_TOKENS.labels(kind="prompt").inc(usage.prompt_tokens or 0)
            metrics.LLM_TOKENS.labels(kind="completion").inc(usage.completion_tokens or 0)
        return response.choices[0].message.content

    except Exception as e:
        logger.error("OpenAI call failed: %s", e)
        is_rate = "rate_limit" in str(e) or "429" in str(e)
        metrics.LLM_ERRORS.labels(reason="rate_limit" if is_rate else "other").inc()
        if is_rate:
            return (
                "⚠️ The AI request hit the OpenAI rate limit — the prompt was "
                "too large or requests came too fast. The verified scanner "
                "findings above are unaffected. Try again in a minute, or "
                "narrow the question to specific files."
            )
        return "An error occurred while contacting the AI. Please try again."