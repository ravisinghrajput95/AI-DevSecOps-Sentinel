import os

from backend.openai_client import get_client
from backend.prompt_engine import SYSTEM_PROMPT

LLM_MODEL = os.environ.get("SENTINEL_LLM_MODEL", "gpt-4o")


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
                "content": str(item[0])
            })
            messages.append({
                "role": "assistant",
                "content": str(item[1])
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
        return "An error occurred while contacting the AI. Please try again."