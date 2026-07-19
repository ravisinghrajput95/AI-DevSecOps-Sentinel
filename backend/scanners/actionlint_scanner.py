# =========================================================
# ACTIONLINT ADAPTER — GitHub Actions workflow security
# Catches script injection via untrusted ${{ }} expressions,
# unpinned actions, and shell bugs inside `run:` blocks —
# CI/CD attack surface that generic IaC scanners miss.
# =========================================================

import json
import os

from backend.scanners.base import is_available, make_finding, run_command

TOOL = "actionlint"

# Script injection ("expression") and credential leaks are the serious
# security classes; everything else is a correctness/hygiene issue.
_HIGH_KINDS = {"expression", "credentials"}


def available() -> bool:
    return is_available(TOOL)


def _workflow_files(workspace_dir: str) -> list:
    workflows = []
    for root, _dirs, files in os.walk(workspace_dir):
        norm = root.replace("\\", "/")
        if "/.github/workflows" not in f"/{norm}/":
            continue
        for name in files:
            if name.lower().endswith((".yml", ".yaml")):
                workflows.append(os.path.join(root, name))
    return workflows


def _severity(issue: dict) -> str:
    msg = (issue.get("message") or "").lower()
    if issue.get("kind") in _HIGH_KINDS or "untrusted" in msg or "injection" in msg:
        return "HIGH"
    return "MEDIUM"


def parse_report(report: list, workspace_dir: str) -> list:
    findings = []
    for issue in report or []:
        filepath = issue.get("filepath", "")
        if workspace_dir and filepath:
            filepath = os.path.relpath(filepath, workspace_dir)
        msg = issue.get("message", "GitHub Actions workflow issue")
        title = msg.split(". ")[0][:200]
        findings.append(make_finding(
            tool=TOOL,
            rule_id=issue.get("kind") or "actionlint",
            severity=_severity(issue),
            file=filepath,
            line=issue.get("line", 0),
            title=title,
            detail=msg,
            guideline="https://github.com/rhysd/actionlint/blob/main/docs/checks.md",
        ))
    return findings


def scan(workspace_dir: str) -> list:
    workflows = _workflow_files(workspace_dir)
    if not workflows:
        return []
    result = run_command([TOOL, "-format", "{{json .}}", *workflows])
    out = result.stdout.strip()
    if not out:
        return []
    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        return []
    return parse_report(report, workspace_dir)
