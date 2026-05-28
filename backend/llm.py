import os
from openai import OpenAI
from dotenv import load_dotenv
from backend.prompt_engine import SYSTEM_PROMPT

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


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
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            temperature=0.2,
            max_tokens=4096
        )
        return response.choices[0].message.content

    except Exception as e:
        print("OpenAI error:", e)
        return "An error occurred while contacting the AI. Please try again."