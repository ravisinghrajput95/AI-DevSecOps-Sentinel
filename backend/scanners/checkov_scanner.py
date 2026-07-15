# =========================================================
# CHECKOV ADAPTER — IaC misconfiguration detection
# Covers Terraform, Kubernetes, Dockerfile, Helm,
# GitHub Actions, docker-compose, CloudFormation.
# =========================================================

import json

from backend.scanners.base import is_available, make_finding, run_command

TOOL = "checkov"


def available() -> bool:
    return is_available(TOOL)


def parse_report(report) -> list:
    """
    Normalize checkov JSON output. Checkov returns either a single
    report dict or a list of dicts (one per framework: terraform,
    dockerfile, kubernetes, ...).
    """
    blocks = report if isinstance(report, list) else [report]
    findings = []

    for block in blocks:
        if not isinstance(block, dict):
            continue
        failed = (block.get("results") or {}).get("failed_checks") or []
        framework = block.get("check_type", "iac")

        for check in failed:
            line_range = check.get("file_line_range") or [0]
            filepath = (check.get("file_path") or "unknown").lstrip("/")
            # OSS checkov often reports severity as null — default MEDIUM
            severity = check.get("severity") or "MEDIUM"

            findings.append(make_finding(
                tool=TOOL,
                rule_id=check.get("check_id", "unknown-check"),
                severity=severity,
                file=filepath,
                line=line_range[0],
                title=check.get("check_name", "Misconfiguration detected"),
                detail=f"Failed {framework} policy check.",
                evidence=str(check.get("resource", "")),
                guideline=check.get("guideline"),
            ))
    return findings


def scan(workspace_dir: str) -> list:
    """Run checkov over the workspace and return normalized findings."""
    # checkov exits non-zero when checks fail — that's expected output
    result = run_command(
        [TOOL, "-d", workspace_dir, "-o", "json", "--quiet"],
        timeout=300,
    )
    if not result.stdout.strip():
        return []
    report = json.loads(result.stdout)
    return parse_report(report)
