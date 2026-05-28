# =========================================================
# INTENT ENGINE
# Classifies user messages before sending to LLM
# =========================================================

ACKNOWLEDGEMENT_PHRASES = [
    "thanks", "thank you", "thank you so much", "thx", "ty",
    "great", "awesome", "perfect", "excellent", "nice", "cool",
    "got it", "understood", "makes sense", "ok", "okay", "ok thanks",
    "sounds good", "good", "noted", "appreciate it", "cheers",
    "that helps", "that helped", "helpful", "very helpful",
    "amazing", "brilliant", "wonderful", "fantastic", "superb",
]

GREETING_PHRASES = [
    "hi", "hello", "hey", "hiya", "howdy",
    "good morning", "good afternoon", "good evening", "good day",
    "what's up", "whats up", "sup", "yo",
]

SMALL_TALK_PHRASES = [
    "how are you", "how are you doing", "how do you do",
    "how's it going", "hows it going", "how are things",
    "what's new", "whats new", "how have you been",
    "are you ok", "are you good", "you good",
    "what are you", "who are you", "tell me about yourself",
    "what can you do", "what do you do",
    "are you an ai", "are you a bot", "are you human",
    "what is your name", "whats your name",
]

CLEAR_PHRASES = [
    "clear", "clear chat", "reset", "start over", "new chat",
    "clear history", "reset chat", "clear context",
]


def detect_intent(user_message: str) -> str:
    """
    Returns one of:
      - acknowledgement
      - greeting
      - small_talk
      - clear
      - chat  (default — send to LLM)
    """
    msg = user_message.lower().strip().rstrip("!.,?")

    if msg in ACKNOWLEDGEMENT_PHRASES:
        return "acknowledgement"

    if msg in GREETING_PHRASES:
        return "greeting"

    if msg in SMALL_TALK_PHRASES:
        return "small_talk"

    if msg in CLEAR_PHRASES:
        return "clear"

    # Partial matches for longer messages
    for phrase in ACKNOWLEDGEMENT_PHRASES:
        if msg == phrase or msg.startswith(phrase + " "):
            return "acknowledgement"

    return "chat"