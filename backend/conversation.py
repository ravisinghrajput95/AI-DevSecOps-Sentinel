# =========================================================
# CONVERSATION MEMORY
# The client sends its own history, but the model only ever
# saw the last 6 turns — so facts stated earlier (a region, a
# budget, a compliance target) were silently forgotten in long
# chats. This module keeps an AUTHORITATIVE server-side turn
# log per session plus a ROLLING SUMMARY of turns that have
# aged out of the verbatim window, so long conversations
# retain their key facts without unbounded token growth.
#
# Cost: the summariser only fires when the window overflows AND
# new turns have rolled off — roughly one small call per turn
# after the window fills. Summaries use a cheap model. If a
# summary call fails, we degrade to recent turns only and never
# break the chat.
# =========================================================

import os

from backend.logging_setup import get_logger
from backend.memory import memory
from backend.openai_client import get_client

logger = get_logger(__name__)

# Verbatim recent turns kept in-context; older ones are summarised.
HISTORY_WINDOW = int(os.environ.get("SENTINEL_HISTORY_WINDOW", "8"))
# Hard cap on the server-side turn log to bound memory/growth.
MAX_TURNS = int(os.environ.get("SENTINEL_MAX_TURNS", "60"))
# Cheap model for summarisation (separate from the chat model).
SUMMARY_MODEL = os.environ.get("SENTINEL_SUMMARY_MODEL", "gpt-4o-mini")
MAX_ITEM_CHARS = 2500

_SUMMARY_INSTRUCTION = (
    "You compress a DevOps/DevSecOps conversation into durable memory. "
    "Given the running summary and new turns, return an UPDATED summary "
    "(<=250 words). PRESERVE every concrete fact the user stated verbatim: "
    "names, numbers, versions, regions, budgets, compliance targets, cluster "
    "and resource names, and decisions made. Drop pleasantries and generic "
    "advice. Output only the summary text."
)


def record_turn(user_message: str, assistant_message: str) -> None:
    """Append a completed turn to the authoritative server-side log."""
    turns = memory["conv_turns"]
    turns.append([str(user_message)[:MAX_ITEM_CHARS],
                  str(assistant_message)[:MAX_ITEM_CHARS]])
    if len(turns) > MAX_TURNS:
        # Drop the oldest, and forget they were summarised so the count
        # stays consistent with the (now shorter) log.
        drop = len(turns) - MAX_TURNS
        turns = turns[drop:]
        memory["conv_summary_covers"] = max(
            0, memory["conv_summary_covers"] - drop)
    memory["conv_turns"] = turns


def _summarise(previous_summary: str, new_turns: list) -> str:
    convo = "\n".join(
        f"User: {u}\nAssistant: {a}" for u, a in new_turns
    )
    prompt = (
        f"Running summary so far:\n{previous_summary or '(none)'}\n\n"
        f"New turns to fold in:\n{convo}"
    )
    resp = get_client().chat.completions.create(
        model=SUMMARY_MODEL,
        messages=[
            {"role": "system", "content": _SUMMARY_INSTRUCTION},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
        max_tokens=400,
    )
    return (resp.choices[0].message.content or "").strip()


def build_context_messages() -> list:
    """
    Return the messages that carry prior-conversation context: an optional
    summary of aged-out turns followed by the last HISTORY_WINDOW verbatim
    turns. Reads/updates the rolling summary in session memory.
    """
    turns = memory["conv_turns"]
    if not turns:
        return []

    # Turns older than the window should be represented by the summary.
    cutoff = max(0, len(turns) - HISTORY_WINDOW)
    covered = memory["conv_summary_covers"]

    if cutoff > covered:
        # New turns have aged out — fold them into the rolling summary.
        try:
            new_summary = _summarise(memory["conv_summary"], turns[covered:cutoff])
            if new_summary:
                memory["conv_summary"] = new_summary
                memory["conv_summary_covers"] = cutoff
        except Exception as e:
            # Never break a chat because summarisation failed — the recent
            # window below still carries the last HISTORY_WINDOW turns.
            logger.warning("conversation summary failed: %s", e)

    messages = []
    summary = memory["conv_summary"]
    if summary:
        messages.append({
            "role": "system",
            "content": (
                "Summary of earlier conversation — facts and decisions to "
                f"remember and honor:\n{summary}"
            ),
        })
    for u, a in turns[-HISTORY_WINDOW:]:
        messages.append({"role": "user", "content": str(u)[:MAX_ITEM_CHARS]})
        messages.append({"role": "assistant", "content": str(a)[:MAX_ITEM_CHARS]})
    return messages


def reset() -> None:
    """Clear conversation memory (on explicit 'clear context')."""
    memory["conv_turns"] = []
    memory["conv_summary"] = ""
    memory["conv_summary_covers"] = 0
