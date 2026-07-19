# =========================================================
# SEMGREP ADAPTER — SAST for application code
# Injection flaws, insecure crypto, dangerous functions in
# Python, JavaScript/TypeScript, Java, Go, shell, ...
# Uses the community registry ruleset (--config auto);
# rules are cached locally after the first run.
# =========================================================

import json
import os

from backend.scanners.base import is_available, make_finding, run_command

TOOL = "semgrep"

SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


def available() -> bool:
    return is_available(TOOL)


def _source_line(path: str, line: int) -> str:
    """Read a specific 1-indexed line from a file (best effort)."""
    if not path or not line or line < 1:
        return ""
    try:
        with open(path, "r", errors="ignore") as fh:
            for i, text in enumerate(fh, start=1):
                if i == line:
                    return text.strip()
    except OSError:
        pass
    return ""


def parse_report(report: dict, workspace_dir: str) -> list:
    findings = []
    for result in (report or {}).get("results") or []:
        extra = result.get("extra") or {}
        abs_path = result.get("path", "unknown")
        line = (result.get("start") or {}).get("line", 0)
        filepath = os.path.relpath(abs_path, workspace_dir) if workspace_dir else abs_path

        # check_id is a long dotted path — keep the meaningful tail
        rule_id = result.get("check_id", "unknown-rule").split(".")[-1]

        references = (extra.get("metadata") or {}).get("references") or []

        # semgrep's `auto` config replaces the matched snippet with the
        # literal "requires login" for registry rules when not signed in —
        # fall back to reading the real source line so evidence isn't junk.
        snippet = (extra.get("lines") or "").strip()
        if not snippet or snippet.lower() == "requires login":
            snippet = _source_line(abs_path, line)

        findings.append(make_finding(
            tool=TOOL,
            rule_id=rule_id,
            severity=SEVERITY_MAP.get(extra.get("severity", ""), "MEDIUM"),
            file=filepath,
            line=line,
            title=(extra.get("message") or "Static analysis finding")[:200],
            detail="Static analysis (SAST) finding in application code.",
            evidence=snippet[:120],
            guideline=references[0] if references else None,
        ))
    return findings


def scan(workspace_dir: str) -> list:
    # --no-git-ignore is required: the workspace dir is gitignored,
    # and semgrep only scans git-tracked files by default.
    # First run downloads the ruleset — allow extra time.
    result = run_command(
        [TOOL, "scan", "--config", "auto", "--json", "--quiet",
         "--no-git-ignore", workspace_dir],
        timeout=600,
    )
    if not result.stdout.strip():
        return []
    return parse_report(json.loads(result.stdout), workspace_dir)
