# =========================================================
# OUTPUT REDACTION — code-level guarantee, not a prompt rule
# The LLM sees raw file contents, so no matter what the
# prompt says it CAN echo a secret back. Every LLM answer is
# scrubbed before leaving the API:
#   1. Exact values of secrets gitleaks detected (kept only
#      in this process, never in prompts or API responses)
#   2. Pattern fallbacks for common credential formats
# =========================================================

import re

# Raw secret values seen by scanners this session. In-memory only —
# same lifetime as the workspace; cleared on "clear context".
_known_secrets = set()

_MIN_SECRET_LENGTH = 6

_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                 # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),       # GitHub tokens
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),     # Slack tokens
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),           # Google API key
]

_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
)

# Values assigned to credential-looking keys in uploaded files.
# Complements gitleaks: it flags e.g. an AWS access key but not
# always the paired secret key, and generic 40-char patterns can't
# be matched globally without masking git SHAs.
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|"
    r"access[_-]?key|secret[_-]?key|auth|credential)s?[\"']?\s*[:=]\s*"
    r"[\"']([^\"'\s]{8,})[\"']"
)


def _mask(value: str) -> str:
    return value[:4] + "*" * min(len(value) - 4, 16)


def remember_secret(value: str):
    """Register a raw secret value found by a scanner."""
    if value and len(value) >= _MIN_SECRET_LENGTH:
        _known_secrets.add(value)


def clear_secrets():
    _known_secrets.clear()


def harvest_secrets(content: str):
    """
    Register every value assigned to a credential-looking key in an
    uploaded file. Values originate from the user's own files, so
    masking them in LLM output is always safe.
    """
    for match in _ASSIGNMENT_RE.finditer(content or ""):
        remember_secret(match.group(1))


def scrub_secrets(text: str) -> str:
    """Mask every known or pattern-matched secret value in text."""
    if not text:
        return text

    # Longest first so partial overlaps can't leave fragments behind
    for secret in sorted(_known_secrets, key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, _mask(secret))

    for pattern in _PATTERNS:
        text = pattern.sub(lambda m: _mask(m.group()), text)

    text = _PRIVATE_KEY_BLOCK.sub("[REDACTED PRIVATE KEY]", text)

    return text
