import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import prompt_engine as pe
from backend.memory import memory
from backend.session import SESSIONS, activate, destroy


@pytest.fixture(autouse=True)
def clean():
    for sid in list(SESSIONS):
        destroy(sid)
    activate("default")
    yield
    for sid in list(SESSIONS):
        destroy(sid)
    activate("default")


def _add_file():
    memory["files"] = [{"name": "main.tf", "content": 'resource "x" "y" {}',
                        "topic": "file", "project": "default"}]
    memory["scan"] = {"findings": [{"severity": "HIGH", "file": "main.tf",
                                    "line": 1, "tool": "checkov", "rule_id": "R",
                                    "title": "t"}],
                      "tools_run": ["checkov"], "tools_missing": []}


# ---- general-knowledge questions the user reported (issues #3, #5) ----

@pytest.mark.parametrize("q", [
    "do you know what are tranistive dependencies?",
    "I want to start with Datadog in project, what could be the easiest way",
    "how do i get started with argocd",
    "what are transitive dependencies",
])
def test_reported_general_questions_route_to_general(q):
    assert pe.is_general_question(q) is True


def test_general_question_does_not_flag_analysis_turn():
    _add_file()
    pe.build_prompt("do you know what are transitive dependencies?", [])
    assert memory.get("_analysis_turn") is False


# ---- generation requests (issue #4) ----

@pytest.mark.parametrize("q", [
    "I have a vulnerable docker file, would you mind share a non vulnerable docker file equivalent to it",
    "rewrite this Dockerfile as a secure version",
    "generate a hardened kubernetes manifest for me",
    "give me a production-ready terraform example",
])
def test_generation_requests_detected(q):
    assert pe.is_generation_request(q) is True


def test_generation_request_does_not_flag_analysis_turn():
    _add_file()
    prompt = pe.build_prompt("share a non-vulnerable Dockerfile equivalent to this", [])
    assert memory.get("_analysis_turn") is False
    assert "WRITE or REWRITE" in prompt  # generation prompt, not audit


def test_generation_routes_to_mode_2_5_without_files():
    # A generation request must hit MODE 2.5 (produce artifact + set the
    # _generation_turn flag) even when no files are uploaded — otherwise
    # the no-files/general-knowledge modes swallow it and the example
    # note never fires.
    memory["files"] = []
    prompt = pe.build_prompt("write me a non-vulnerable Dockerfile for a python app", [])
    assert memory.get("_generation_turn") is True
    assert memory.get("_analysis_turn") is False
    assert "WRITE or REWRITE" in prompt


def test_plain_and_knowledge_messages_are_not_generation_turns():
    memory["files"] = []
    for q in ("hello", "what is a dockerfile"):
        memory["_generation_turn"] = False
        pe.build_prompt(q, [])
        assert memory.get("_generation_turn") is False, q


def test_generate_all_fixes_is_not_a_generation_request():
    # The 'Generate All Fixes' quick action must still run analysis
    assert pe.is_generation_request("generate all fixes") is False


# ---- genuine file analysis still flags the analysis turn ----

def test_file_analysis_flags_analysis_turn():
    _add_file()
    pe.build_prompt("audit this terraform for misconfigurations", [])
    assert memory.get("_analysis_turn") is True
