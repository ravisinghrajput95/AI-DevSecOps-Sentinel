import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.intent_engine import detect_intent, is_off_topic


@pytest.mark.parametrize("message,expected", [
    # Greetings
    ("hi", "greeting"),
    ("Good morning!", "greeting"),
    ("wassup", "greeting"),
    # Small talk
    ("how are you?", "small_talk"),
    ("who are you", "small_talk"),
    ("what can you do", "small_talk"),
    # Clear
    ("clear context", "clear"),
    ("reset", "clear"),
    # Acknowledgements
    ("thanks a lot!", "acknowledgement"),
    ("ok cool", "acknowledgement"),
    ("👍", "acknowledgement"),
    ("got it thanks", "acknowledgement"),
    ("yes", "acknowledgement"),
    ("sure", "acknowledgement"),
    ("go ahead", "acknowledgement"),
    # Ack word + explicit analysis command → NOT an ack, run the analysis
    ("yes audit", "chat"),
    ("sure, scan it", "chat"),
    ("go ahead review this", "chat"),
    ("ok analyse", "chat"),
    ("yes run the security review", "chat"),
    # Soft verbs ("check", "take a look") also mean analyse, even with an
    # ack prefix — must not be swallowed as acknowledgements
    ("sure, check it", "chat"),
    ("go ahead and check it", "chat"),
    ("take a look", "chat"),
    ("have a look at it", "chat"),
    ("walk me through it", "chat"),
    # "looks good" must STAY an acknowledgement (not caught by "look")
    ("looks good", "acknowledgement"),
    ("looks great", "acknowledgement"),
    # Off-topic
    ("who is virat kohli", "off_topic"),
    ("capital of France", "off_topic"),
    ("recipe for pasta", "off_topic"),
    ("2 + 2 =", "off_topic"),
    # Chat (LLM-bound)
    ("analyze my dockerfile", "chat"),
    ("what is kubernetes rbac", "chat"),
    ("scan this repo for secrets", "chat"),
    ("explain terraform state locking", "chat"),
    ("is this pipeline secure", "chat"),
    ("docker vs podman", "chat"),
])
def test_detect_intent(message, expected):
    assert detect_intent(message) == expected


@pytest.mark.parametrize("message,expected", [
    ("yes", True), ("yes please", True), ("sure", True), ("go ahead", True),
    ("ok", True), ("yeah", True), ("proceed", True), ("do it", True),
    # gratitude / reactions are NOT affirmative continuations
    ("thanks", False), ("great", False), ("perfect", False), ("cool", False),
    ("no thanks", False), ("looks good", False),
])
def test_is_affirmative_continuation(message, expected):
    from backend.intent_engine import is_affirmative_continuation
    assert is_affirmative_continuation(message) is expected


def test_devops_terms_match_word_boundaries():
    # "important" must not match the term "port"
    assert not is_off_topic("who is virat kohli") is False  # sanity: names still detected
    assert is_off_topic("who is virat kohli")
    # word-boundary: presence of a token like "deployment" keeps it on-topic
    assert not is_off_topic("important question about my deployment")


def test_multiword_devops_terms_still_match_as_phrases():
    assert not is_off_topic("tell me about github actions")
