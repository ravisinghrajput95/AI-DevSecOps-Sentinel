# =========================================================
# HADOLINT ADAPTER — Dockerfile best-practice linting
# =========================================================

import json
import os

from backend.scanners.base import find_files, is_available, make_finding, run_command

TOOL = "hadolint"

SEVERITY_MAP = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "info": "LOW",
    "style": "LOW",
}


def available() -> bool:
    return is_available(TOOL)


def _is_dockerfile(name: str) -> bool:
    lower = name.lower()
    return lower == "dockerfile" or lower.endswith(".dockerfile") or lower.startswith("dockerfile.")


def parse_report(report: list, workspace_dir: str) -> list:
    findings = []
    for issue in report or []:
        code = issue.get("code", "unknown-rule")
        filepath = issue.get("file", "Dockerfile")
        if workspace_dir:
            filepath = os.path.relpath(filepath, workspace_dir)

        guideline = None
        if code.startswith("DL"):
            guideline = f"https://github.com/hadolint/hadolint/wiki/{code}"

        findings.append(make_finding(
            tool=TOOL,
            rule_id=code,
            severity=SEVERITY_MAP.get(issue.get("level", ""), "LOW"),
            file=filepath,
            line=issue.get("line", 0),
            title=issue.get("message", "Dockerfile issue"),
            detail="Dockerfile best-practice violation.",
            guideline=guideline,
        ))
    return findings


def scan(workspace_dir: str) -> list:
    dockerfiles = find_files(workspace_dir, _is_dockerfile)
    if not dockerfiles:
        return []
    # --no-fail: findings are output, not a process error
    result = run_command(
        [TOOL, "--format", "json", "--no-fail", *dockerfiles],
    )
    if not result.stdout.strip():
        return []
    return parse_report(json.loads(result.stdout), workspace_dir)
