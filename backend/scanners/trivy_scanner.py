# =========================================================
# TRIVY ADAPTER — vulnerable dependency detection
# Scans lockfiles/manifests (requirements.txt, package-lock,
# pom.xml, go.mod, Gemfile.lock, ...) for known CVEs.
# Scoped to --scanners vuln: misconfigs are checkov's job,
# secrets are gitleaks' job.
# =========================================================

import json

from backend.scanners.base import is_available, make_finding, run_command

TOOL = "trivy"


def available() -> bool:
    return is_available(TOOL)


def parse_report(report: dict) -> list:
    findings = []
    for result in (report or {}).get("Results") or []:
        target = result.get("Target", "unknown")
        for vuln in result.get("Vulnerabilities") or []:
            pkg = vuln.get("PkgName", "unknown")
            installed = vuln.get("InstalledVersion", "?")
            fixed = vuln.get("FixedVersion")
            fix_note = f" (fix: upgrade to {fixed})" if fixed else " (no fix released yet)"

            findings.append(make_finding(
                tool=TOOL,
                rule_id=vuln.get("VulnerabilityID", "unknown-cve"),
                severity=vuln.get("Severity", "MEDIUM"),
                file=target,
                line=0,
                title=f"{pkg} {installed}: {vuln.get('Title', 'known vulnerability')}",
                detail=(vuln.get("Description") or "")[:300],
                evidence=f"{pkg}=={installed}{fix_note}",
                guideline=vuln.get("PrimaryURL"),
            ))
    return findings


def scan(workspace_dir: str) -> list:
    # First run downloads the vulnerability DB — allow extra time
    result = run_command(
        [TOOL, "fs", "--scanners", "vuln", "--format", "json", "--quiet", workspace_dir],
        timeout=300,
    )
    if not result.stdout.strip():
        return []
    return parse_report(json.loads(result.stdout))
