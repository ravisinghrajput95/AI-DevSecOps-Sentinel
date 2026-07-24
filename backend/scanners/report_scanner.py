# =========================================================
# SECURITY-REPORT / SBOM IMPORT
# Enterprises already run scanners in CI. When a user uploads
# a Trivy/Semgrep JSON, a SARIF report, or a CycloneDX/SPDX
# SBOM, treat it as STRUCTURED input — parse it into the same
# verified-findings panel — instead of letting the LLM merely
# summarize the raw text (which produced zero findings before).
#
#   Trivy JSON / SARIF -> parsed directly (they already carry findings)
#   CycloneDX / SPDX SBOM -> `trivy sbom` for real component->CVE lookup
# =========================================================

import json
import os

from backend.logging_setup import get_logger
from backend.scanners.base import (
    find_files,
    is_available,
    make_finding,
    run_command,
)

logger = get_logger(__name__)

TOOL = "report-import"

_MAX_PER_REPORT = 500  # guard against a giant uploaded report

# SARIF result.level -> our severity
_SARIF_LEVEL = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
_TRIVY_SEV = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
              "LOW": "LOW", "UNKNOWN": "INFO"}


def available() -> bool:
    # Pure-Python parsing needs nothing; the SBOM path degrades gracefully
    # if trivy is missing (handled in _scan_sbom).
    return True


def _detect(data: dict) -> str:
    if not isinstance(data, dict):
        return ""
    schema = str(data.get("$schema", "")).lower()
    if "sarif" in schema or ("runs" in data and "version" in data and
                             isinstance(data.get("runs"), list)):
        return "sarif"
    if "SchemaVersion" in data and "Results" in data:
        return "trivy"
    if data.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if "spdxVersion" in data or data.get("SPDXID"):
        return "spdx"
    return ""


def _parse_sarif(data: dict, rel: str) -> list:
    out = []
    for run in data.get("runs", []) or []:
        driver = (((run.get("tool") or {}).get("driver")) or {}).get("name", "sarif")
        for res in (run.get("results") or [])[:_MAX_PER_REPORT]:
            level = str(res.get("level", "warning")).lower()
            sev = _SARIF_LEVEL.get(level, "MEDIUM")
            # SARIF may carry a numeric security-severity (0-10) instead.
            props = res.get("properties") or {}
            ss = props.get("security-severity")
            if ss is not None:
                try:
                    v = float(ss)
                    sev = ("CRITICAL" if v >= 9 else "HIGH" if v >= 7
                           else "MEDIUM" if v >= 4 else "LOW")
                except (TypeError, ValueError):
                    pass
            loc = (res.get("locations") or [{}])[0]
            phys = (loc.get("physicalLocation") or {})
            uri = ((phys.get("artifactLocation") or {}).get("uri")) or rel
            line = ((phys.get("region") or {}).get("startLine")) or 0
            msg = (res.get("message") or {}).get("text", res.get("ruleId", "finding"))
            out.append(make_finding(
                tool=f"{driver} (imported)", rule_id=str(res.get("ruleId", "sarif")),
                severity=sev, file=uri, line=int(line) if str(line).isdigit() else 0,
                title=msg[:200], detail="Imported from uploaded SARIF report."))
    return out


def _parse_trivy(data: dict, rel: str) -> list:
    out = []
    for result in data.get("Results", []) or []:
        target = result.get("Target", rel)
        for v in (result.get("Vulnerabilities") or []):
            sev = _TRIVY_SEV.get(str(v.get("Severity", "")).upper(), "MEDIUM")
            fixed = v.get("FixedVersion")
            ev = f"{v.get('PkgName','?')} {v.get('InstalledVersion','?')}" + (
                f" -> fix {fixed}" if fixed else "")
            out.append(make_finding(
                tool="trivy (imported)", rule_id=str(v.get("VulnerabilityID", "CVE")),
                severity=sev, file=target, line=0,
                title=(v.get("Title") or v.get("VulnerabilityID") or "vulnerability")[:200],
                evidence=ev, detail="Imported from uploaded Trivy report."))
            if len(out) >= _MAX_PER_REPORT:
                return out
        for m in (result.get("Misconfigurations") or []):
            sev = _TRIVY_SEV.get(str(m.get("Severity", "")).upper(), "MEDIUM")
            out.append(make_finding(
                tool="trivy (imported)", rule_id=str(m.get("ID", "misconfig")),
                severity=sev, file=target, line=(m.get("CauseMetadata") or {}).get("StartLine", 0) or 0,
                title=(m.get("Title") or "misconfiguration")[:200],
                detail="Imported from uploaded Trivy report."))
            if len(out) >= _MAX_PER_REPORT:
                return out
    return out


def _scan_sbom(path: str, rel: str) -> list:
    """Run trivy against an uploaded SBOM to get real component->CVE findings."""
    if not is_available("trivy"):
        logger.info("SBOM %s uploaded but trivy unavailable — skipping", rel)
        return []
    try:
        result = run_command(
            ["trivy", "sbom", "--format", "json", "--quiet", "--skip-db-update", path],
            timeout=90)
        if not result.stdout.strip():
            # DB may be cold (skip-db-update failed) — one bounded retry that
            # is allowed to fetch the DB.
            result = run_command(
                ["trivy", "sbom", "--format", "json", "--quiet", path], timeout=90)
        if not result.stdout.strip():
            return []
        return _parse_trivy(json.loads(result.stdout), rel)
    except Exception as e:
        logger.warning("trivy sbom failed for %s: %s", rel, e)
        return []


def scan(workspace_dir: str) -> list:
    findings = []
    for path in find_files(workspace_dir,
                           lambda n: n.lower().endswith((".json", ".sarif"))):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except Exception:
            continue  # not JSON we can parse — leave it to the LLM
        rel = os.path.relpath(path, workspace_dir)
        kind = _detect(data)
        if kind == "sarif":
            findings += _parse_sarif(data, rel)
        elif kind == "trivy":
            findings += _parse_trivy(data, rel)
        elif kind in ("cyclonedx", "spdx"):
            findings += _scan_sbom(path, rel)
        if findings:
            logger.info("report-import: %s (%s) -> %d findings", rel, kind, len(findings))
    return findings
