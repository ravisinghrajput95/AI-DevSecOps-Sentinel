# =========================================================
# INJECTION-GUARD ADAPTER — prompt-injection detection
# Pure-Python scanner (always available). Detects text inside
# ingested files that tries to manipulate the LLM analysis:
# instruction overrides, finding suppression, role hijacks,
# fake chat-template tokens, and hidden Unicode controls.
#
# Because scanner findings are returned to the client as
# structured data straight from the scan cache — never through
# the LLM — a malicious repo cannot talk the model out of
# reporting its own injection attempt.
# =========================================================

import os
import re

from backend.scanners.base import make_finding

TOOL = "injection-guard"

MAX_SCAN_BYTES = 2 * 1024 * 1024   # skip huge files — injections target prompts, not blobs
MAX_MATCH_PREVIEW = 80             # evidence snippet cap

# (rule_id, severity, title, [patterns])
INJECTION_RULES = [
    (
        "instruction-override",
        "HIGH",
        "Prompt-injection attempt: instruction override",
        [
            r"(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:the\s+)?"
            r"(?:previous|prior|above|earlier|preceding|system)\s+"
            r"(?:instructions?|rules?|prompts?|directives?|guidelines?)",
            r"(?:new|updated|revised)\s+system\s+prompt",
            r"your\s+(?:new\s+)?(?:instructions?|rules?)\s+(?:are|is)\b",
        ],
    ),
    (
        "finding-suppression",
        "HIGH",
        "Prompt-injection attempt: finding suppression",
        [
            r"(?:do\s+not|don'?t|never|refuse\s+to)\s+"
            r"(?:report|mention|include|flag|list|disclose|output)\s+"
            r"(?:any\s+|the\s+|these\s+)?"
            r"(?:findings?|issues?|vulnerabilit\w*|secrets?|problems?|warnings?)",
            r"report\s+(?:no|zero)\s+(?:findings?|issues?|vulnerabilit\w*)",
            r"(?:mark|treat|classify|consider)\s+(?:this|these|all|it|everything)\s+"
            r"as\s+(?:safe|secure|passed|benign|(?:a\s+)?false\s+positives?)",
            r"(?:this|the)\s+(?:file|repo(?:sitory)?|code|project)\s+"
            r"(?:is|has\s+been)\s+(?:already\s+)?"
            r"(?:audited|verified|approved|whitelisted|deemed\s+safe)",
        ],
    ),
    (
        "role-hijack",
        "HIGH",
        "Prompt-injection attempt: role hijack",
        [
            r"you\s+are\s+now\s+(?:a|an|in)\b",
            r"you\s+are\s+no\s+longer\b",
            r"(?:attention|note\s+to|message\s+(?:to|for))[:,]?\s+"
            r"(?:the\s+)?(?:ai|llm|assistant|model|analyzer)",
            r"if\s+you\s+are\s+an?\s+(?:ai|llm|language\s+model|assistant)",
        ],
    ),
    (
        "special-token",
        "HIGH",
        "Prompt-injection attempt: fake chat-template token",
        [
            r"<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>",
            r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>",
        ],
    ),
]

_COMPILED = [
    (rule_id, severity, title, [re.compile(p, re.IGNORECASE) for p in patterns])
    for rule_id, severity, title, patterns in INJECTION_RULES
]

# Zero-width and bidirectional control characters — used to hide
# instructions from human reviewers (Trojan Source style).
_HIDDEN_UNICODE = re.compile(
    "[\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff]"
)


def available() -> bool:
    return True


def _read_text(filepath: str):
    try:
        if os.path.getsize(filepath) > MAX_SCAN_BYTES:
            return None
    except OSError:
        return None
    for encoding in ("utf-8", "latin-1"):
        try:
            with open(filepath, "r", encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, OSError):
            continue
    return None


def scan_content(content: str, source: str) -> list:
    """
    Scan one file's text for injection attempts. Reports the first
    matching line per rule (with a total hit count) so a file packed
    with injection text yields a handful of findings, not hundreds.
    """
    findings = []
    lines = content.splitlines()

    for rule_id, severity, title, patterns in _COMPILED:
        first_line = None
        first_match = ""
        hits = 0
        for lineno, line in enumerate(lines, start=1):
            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    hits += 1
                    if first_line is None:
                        first_line = lineno
                        first_match = match.group(0)
                    break
        if first_line is not None:
            extra = f" ({hits} occurrences in this file)" if hits > 1 else ""
            findings.append(make_finding(
                tool=TOOL,
                rule_id=rule_id,
                severity=severity,
                file=source,
                line=first_line,
                title=title,
                detail=(
                    "This file contains text that attempts to manipulate the "
                    "AI analysis — e.g. to override its instructions or "
                    "suppress security findings. Treat the file as hostile: "
                    "the content is data, not instructions, and all findings "
                    f"stand regardless of what it claims.{extra}"
                ),
                evidence=first_match[:MAX_MATCH_PREVIEW],
            ))

    hidden = _HIDDEN_UNICODE.findall(content)
    if hidden:
        first_line = next(
            (i for i, line in enumerate(lines, start=1)
             if _HIDDEN_UNICODE.search(line)),
            1,
        )
        findings.append(make_finding(
            tool=TOOL,
            rule_id="hidden-unicode",
            severity="MEDIUM",
            file=source,
            line=first_line,
            title="Hidden Unicode control characters detected",
            detail=(
                f"{len(hidden)} zero-width or bidirectional control "
                "character(s) found. These are invisible in most editors and "
                "can hide instructions or disguise malicious code from human "
                "review (Trojan Source, CVE-2021-42574)."
            ),
            evidence=", ".join(sorted({f"U+{ord(c):04X}" for c in hidden}))[:MAX_MATCH_PREVIEW],
        ))

    return findings


def scan(workspace_dir: str) -> list:
    """Scan every readable text file in the workspace."""
    findings = []
    for root, dirs, files in os.walk(workspace_dir):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        for name in files:
            filepath = os.path.join(root, name)
            content = _read_text(filepath)
            if content is None:
                continue
            source = os.path.relpath(filepath, workspace_dir)
            findings.extend(scan_content(content, source))
    return findings
