# =========================================================
# ACTIONLINT ADAPTER — GitHub Actions workflow security
# Catches script injection via untrusted ${{ }} expressions,
# unpinned actions, and shell bugs inside `run:` blocks —
# CI/CD attack surface that generic IaC scanners miss.
# =========================================================

import json
import os
import re

from backend.scanners.base import is_available, make_finding, run_command

TOOL = "actionlint"

# Script injection ("expression") and credential leaks are the serious
# security classes; everything else is a correctness/hygiene issue.
_HIGH_KINDS = {"expression", "credentials"}


def available() -> bool:
    return is_available(TOOL)


_WF_ON = re.compile(r"(?m)^on\s*:")
_WF_JOBS = re.compile(r"(?m)^jobs\s*:")


def _looks_like_workflow(path: str) -> bool:
    """A YAML with top-level `on:` and `jobs:` is a GitHub Actions workflow,
    even when uploaded standalone (outside .github/workflows/)."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(4000)
    except Exception:
        return False
    return bool(_WF_ON.search(head)) and bool(_WF_JOBS.search(head))


def _workflow_files(workspace_dir: str) -> list:
    workflows = []
    for root, _dirs, files in os.walk(workspace_dir):
        norm = root.replace("\\", "/")
        in_wf_dir = "/.github/workflows" in f"/{norm}/"
        for name in files:
            if not name.lower().endswith((".yml", ".yaml")):
                continue
            path = os.path.join(root, name)
            # Lint files in .github/workflows/ OR any standalone YAML that
            # is structurally a workflow — so a bare "ci.yml" upload still
            # gets its expression-injection / unpinned-action checks.
            if in_wf_dir or _looks_like_workflow(path):
                workflows.append(path)
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
