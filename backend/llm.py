import os

from backend.openai_client import get_client
from backend.prompt_engine import SYSTEM_PROMPT

LLM_MODEL = os.environ.get("SENTINEL_LLM_MODEL", "gpt-4o")

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

    try:
        response = get_client().chat.completions.create(
            model=LLM_MODEL,
            messages=messages,
            temperature=0.2,
            max_tokens=4096
        )
        return response.choices[0].message.content

    except Exception as e:
        print("OpenAI error:", e)
        if "rate_limit" in str(e) or "429" in str(e):
            return (
                "⚠️ The AI request hit the OpenAI rate limit — the prompt was "
                "too large or requests came too fast. The verified scanner "
                "findings above are unaffected. Try again in a minute, or "
                "narrow the question to specific files."
            )
        return "An error occurred while contacting the AI. Please try again."