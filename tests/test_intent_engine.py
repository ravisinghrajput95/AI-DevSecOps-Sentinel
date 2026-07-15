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


def test_devops_terms_match_word_boundaries():
    # "important" must not match the term "port"
    assert not is_off_topic("who is virat kohli") is False  # sanity: names still detected
    assert is_off_topic("who is virat kohli")
    # word-boundary: presence of a token like "deployment" keeps it on-topic
    assert not is_off_topic("important question about my deployment")


def test_multiword_devops_terms_still_match_as_phrases():
    assert not is_off_topic("tell me about github actions")
