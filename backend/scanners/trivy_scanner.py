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
    # --offline-scan: never call external services (e.g. Maven Central
    # for Java transitive deps) during analysis — those calls are slow,
    # rate-limited, and make results non-deterministic. Lockfile-based
    # detection (npm/pip/go/...) is fully local. The vulnerability DB
    # download on first run is separate and unaffected.
    result = run_command(
        [TOOL, "fs", "--scanners", "vuln", "--offline-scan",
         "--format", "json", "--quiet", workspace_dir],
        timeout=300,
    )
    if not result.stdout.strip():
        # A hard failure (e.g. DB download error) must surface as a
        # scanner error, not masquerade as a clean empty result
        if result.returncode != 0:
            raise RuntimeError(
                f"trivy exited {result.returncode}: {result.stderr.strip()[:300]}"
            )
        return []
    return parse_report(json.loads(result.stdout))
