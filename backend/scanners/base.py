# =========================================================
# SCANNER BASE
# Shared helpers for all scanner adapters. Every adapter
# returns a list of normalized finding dicts:
#
#   {
#     "tool":      "gitleaks",
#     "rule_id":   "aws-access-key",
#     "severity":  "CRITICAL",   # CRITICAL / HIGH / MEDIUM / LOW / INFO
#     "file":      "terraform/main.tf",
#     "line":      12,
#     "title":     "AWS Access Key detected",
#     "detail":    "...",
#     "evidence":  "AKIA************",   # secrets always redacted
#     "guideline": "https://..." or None,
#   }
# =========================================================

import os
import shutil
import subprocess

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def find_files(workspace_dir: str, predicate) -> list:
    """Walk the workspace and return paths matching predicate(filename)."""
    matches = []
    for root, _dirs, files in os.walk(workspace_dir):
        for name in files:
            if predicate(name):
                matches.append(os.path.join(root, name))
    return matches


def is_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_command(cmd: list, timeout: int = 120) -> subprocess.CompletedProcess:
    """
    Run a scanner CLI. Returns the completed process; callers decide
    what exit codes mean (most scanners exit non-zero on findings).
    """
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def make_finding(
    tool: str,
    rule_id: str,
    severity: str,
    file: str,
    line: int,
    title: str,
    detail: str = "",
    evidence: str = "",
    guideline: str = None,
) -> dict:
    severity = (severity or "MEDIUM").upper()
    if severity not in SEVERITY_ORDER:
        severity = "MEDIUM"
    return {
        "tool": tool,
        "rule_id": rule_id,
        "severity": severity,
        "file": file,
        "line": line,
        "title": title,
        "detail": detail,
        "evidence": evidence,
        "guideline": guideline,
    }


def redact_secret(secret: str, keep: int = 4) -> str:
    """Keep the first few chars for identification, mask the rest."""
    if not secret:
        return ""
    if len(secret) <= keep:
        return "*" * len(secret)
    return secret[:keep] + "*" * min(len(secret) - keep, 16)
