# =========================================================
# KUBESEC ADAPTER — Kubernetes manifest risk scoring
# Runs per-manifest; only YAML files that look like K8s
# resources (contain a top-level "kind:") are scanned.
# critical → HIGH findings, advise → LOW suggestions.
# =========================================================

import json
import os

from backend.scanners.base import find_files, is_available, make_finding, run_command

TOOL = "kubesec"


def available() -> bool:
    return is_available(TOOL)


def _is_k8s_manifest(path: str) -> bool:
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            head = f.read(4000)
        return "kind:" in head and "apiVersion:" in head
    except OSError:
        return False


def parse_report(report: list, filepath: str) -> list:
    findings = []
    for entry in report or []:
        if not isinstance(entry, dict) or not entry.get("valid", True):
            continue
        obj = entry.get("object", "")
        scoring = entry.get("scoring") or {}

        for item in scoring.get("critical") or []:
            findings.append(make_finding(
                tool=TOOL,
                rule_id=item.get("id", "unknown-rule"),
                severity="HIGH",
                file=filepath,
                line=0,
                title=f"{obj}: {item.get('reason', 'critical security issue')}",
                detail=f"Selector: {item.get('selector', '')}",
                evidence=f"score impact: {item.get('points', '?')}",
            ))

        for item in scoring.get("advise") or []:
            findings.append(make_finding(
                tool=TOOL,
                rule_id=item.get("id", "unknown-rule"),
                severity="LOW",
                file=filepath,
                line=0,
                title=f"{obj}: {item.get('reason', 'hardening advice')}",
                detail=f"Selector: {item.get('selector', '')}",
            ))
    return findings


def scan(workspace_dir: str) -> list:
    manifests = find_files(
        workspace_dir,
        lambda n: n.lower().endswith((".yaml", ".yml")),
    )
    findings = []
    for path in manifests:
        if not _is_k8s_manifest(path):
            continue
        result = run_command([TOOL, "scan", path])
        if not result.stdout.strip():
            continue
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            continue
        rel = os.path.relpath(path, workspace_dir)
        findings.extend(parse_report(report, rel))
    return findings
