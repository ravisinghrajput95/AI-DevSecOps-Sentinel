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


def _evidence(check: dict) -> str:
    """Real code snippet for the finding, from checkov's code_block.

    Uses the specific offending line (file_line_range start) rather than the
    whole block — file-level checks (e.g. missing HEALTHCHECK) carry the
    entire file in code_block, which would dump the file as "evidence".
    Never surfaces raw secret values (CKV_SECRET_* blocks contain the
    plaintext secret) — those carry a redacted form in the LLM notes.
    """
    if (check.get("check_id") or "").upper().startswith("CKV_SECRET"):
        return ""
    by_line = {}
    for row in check.get("code_block") or []:
        if isinstance(row, (list, tuple)) and len(row) == 2:
            text = str(row[1]).strip()
            if text:
                by_line[row[0]] = text
    target = (check.get("file_line_range") or [0])[0]
    snippet = by_line.get(target) or next(iter(by_line.values()), "")
    return (snippet or str(check.get("resource", "")))[:120]


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
                evidence=_evidence(check),
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
