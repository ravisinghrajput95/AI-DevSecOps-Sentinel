# =========================================================
# GITLEAKS ADAPTER — secret detection
# =========================================================

import json
import os
import tempfile

from backend.scanners.base import (
    is_available,
    make_finding,
    redact_secret,
    run_command,
)

TOOL = "gitleaks"


def available() -> bool:
    return is_available(TOOL)


def parse_report(report: list, workspace_dir: str) -> list:
    """Normalize a gitleaks JSON report (list of leak dicts)."""
    findings = []
    for leak in report or []:
        filepath = leak.get("File", "unknown")
        # Report paths are absolute inside the scanned dir — make relative
        if workspace_dir and filepath.startswith(workspace_dir):
            filepath = os.path.relpath(filepath, workspace_dir)

        findings.append(make_finding(
            tool=TOOL,
            rule_id=leak.get("RuleID", "unknown-rule"),
            severity="CRITICAL",
            file=filepath,
            line=leak.get("StartLine", 0),
            title=leak.get("Description", "Hardcoded secret detected"),
            detail=(
                "A hardcoded secret was detected by gitleaks. "
                "Rotate this credential immediately — treat it as compromised."
            ),
            evidence=redact_secret(leak.get("Secret", "")),
        ))
    return findings


def scan(workspace_dir: str) -> list:
    """Run gitleaks over the workspace and return normalized findings."""
    report_path = tempfile.mktemp(suffix=".json")
    try:
        # --exit-code 0: don't treat "leaks found" as a process error
        run_command([
            TOOL, "detect",
            "--no-git",
            "--source", workspace_dir,
            "--report-format", "json",
            "--report-path", report_path,
            "--exit-code", "0",
        ])
        if not os.path.exists(report_path):
            return []
        with open(report_path) as f:
            report = json.load(f)
        return parse_report(report, workspace_dir)
    finally:
        if os.path.exists(report_path):
            os.remove(report_path)
