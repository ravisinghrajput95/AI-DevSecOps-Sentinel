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


def parse_report(report: dict, workspace_dir: str) -> list:
    findings = []
    for result in (report or {}).get("results") or []:
        extra = result.get("extra") or {}
        filepath = result.get("path", "unknown")
        if workspace_dir:
            filepath = os.path.relpath(filepath, workspace_dir)

        # check_id is a long dotted path — keep the meaningful tail
        rule_id = result.get("check_id", "unknown-rule").split(".")[-1]

        references = (extra.get("metadata") or {}).get("references") or []

        findings.append(make_finding(
            tool=TOOL,
            rule_id=rule_id,
            severity=SEVERITY_MAP.get(extra.get("severity", ""), "MEDIUM"),
            file=filepath,
            line=(result.get("start") or {}).get("line", 0),
            title=(extra.get("message") or "Static analysis finding")[:200],
            detail="Static analysis (SAST) finding in application code.",
            evidence=(extra.get("lines") or "")[:120],
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
