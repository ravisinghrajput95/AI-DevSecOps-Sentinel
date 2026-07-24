# Conversation memory: server-side turn log + rolling summary so facts
# survive past the verbatim window. Summariser is mocked (no OpenAI).
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import conversation as cv
from backend.memory import memory
from backend.session import SESSIONS, activate, destroy


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for sid in list(SESSIONS):
        destroy(sid)
    activate("default")
    cv.reset()
    # small window keeps tests concise
    monkeypatch.setattr(cv, "HISTORY_WINDOW", 2)
    yield
    for sid in list(SESSIONS):
        destroy(sid)
    activate("default")


def _mock_summariser(monkeypatch):
    calls = []
    def fake(prev, new):
        calls.append((prev, list(new)))
        facts = "; ".join(u for u, a in new)
        return (prev + " | " if prev else "") + f"facts[{facts}]"
    monkeypatch.setattr(cv, "_summarise", fake)
    return calls


def test_record_turn_and_cap(monkeypatch):
    monkeypatch.setattr(cv, "MAX_TURNS", 3)
    for i in range(5):
        cv.record_turn(f"u{i}", f"a{i}")
    turns = memory["conv_turns"]
    assert len(turns) == 3
    assert turns[0][0] == "u2"  # oldest two dropped


def test_short_conversation_no_summary(monkeypatch):
    calls = _mock_summariser(monkeypatch)
    cv.record_turn("hello", "hi")
    cv.record_turn("region is eu-west-2", "noted")
    msgs = cv.build_context_messages()
    assert len(calls) == 0                      # within window -> no summary
    assert memory["conv_summary"] == ""
    assert [m["role"] for m in msgs] == ["user", "assistant", "user", "assistant"]


def test_long_conversation_summarises_aged_turns(monkeypatch):
    calls = _mock_summariser(monkeypatch)
    for u, a in [("region is eu-west-2", "ok"), ("budget is $4200", "ok"),
                 ("q3", "a3"), ("q4", "a4")]:
        cv.record_turn(u, a)
    msgs = cv.build_context_messages()
    # window=2 -> first 2 turns aged out and summarised
    assert len(calls) == 1
    assert memory["conv_summary_covers"] == 2
    summary_msg = msgs[0]
    assert summary_msg["role"] == "system"
    assert "eu-west-2" in summary_msg["content"] and "$4200" in summary_msg["content"]
    # last 2 turns are verbatim
    assert msgs[-4:] == [
        {"role": "user", "content": "q3"}, {"role": "assistant", "content": "a3"},
        {"role": "user", "content": "q4"}, {"role": "assistant", "content": "a4"}]


def test_summary_is_incremental(monkeypatch):
    calls = _mock_summariser(monkeypatch)
    for u, a in [("f1", "ok"), ("f2", "ok"), ("f3", "ok"), ("f4", "ok")]:
        cv.record_turn(u, a)
    cv.build_context_messages()            # summarises f1,f2
    assert len(calls) == 1
    cv.record_turn("f5", "ok")             # f3 now ages out
    cv.build_context_messages()
    assert len(calls) == 2
    assert calls[1][1] == [["f3", "ok"]]   # only the newly-aged turn
    assert memory["conv_summary_covers"] == 3


def test_summary_failure_degrades_gracefully(monkeypatch):
    def boom(prev, new):
        raise RuntimeError("openai down")
    monkeypatch.setattr(cv, "_summarise", boom)
    for i in range(4):
        cv.record_turn(f"u{i}", f"a{i}")
    msgs = cv.build_context_messages()     # must not raise
    assert memory["conv_summary"] == ""    # no summary, but chat survives
    assert any(m["content"] == "u3" for m in msgs)  # recent window still present


def test_reset_clears(monkeypatch):
    cv.record_turn("x", "y")
    cv.reset()
    assert memory["conv_turns"] == [] and memory["conv_summary"] == ""
    assert memory["conv_summary_covers"] == 0
