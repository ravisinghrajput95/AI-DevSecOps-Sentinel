# =========================================================
# SCANNER REGISTRY
# Runs every available scanner over the workspace and
# returns one merged, severity-sorted findings list.
# A missing or crashing scanner never breaks ingestion.
# =========================================================

from backend.scanners.base import SEVERITY_ORDER
from backend.scanners import gitleaks_scanner, checkov_scanner

SCANNERS = [gitleaks_scanner, checkov_scanner]


def scanner_status() -> dict:
    """Availability of each registered scanner (for /health)."""
    return {s.TOOL: s.available() for s in SCANNERS}


def run_all_scanners(workspace_dir: str) -> dict:
    findings = []
    tools_run = []
    tools_missing = []

    for scanner in SCANNERS:
        if not scanner.available():
            tools_missing.append(scanner.TOOL)
            continue
        try:
            findings.extend(scanner.scan(workspace_dir))
            tools_run.append(scanner.TOOL)
        except Exception as e:
            print(f"Scanner error ({scanner.TOOL}): {e}")

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["file"], f["line"]))

    print(f"\n=== SCAN COMPLETE: {len(findings)} findings "
          f"(ran: {tools_run or 'none'}, missing: {tools_missing or 'none'}) ===")

    return {
        "findings": findings,
        "tools_run": tools_run,
        "tools_missing": tools_missing,
    }
