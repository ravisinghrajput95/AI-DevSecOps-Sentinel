# =========================================================
# SCANNER REGISTRY
# Runs every available scanner over the workspace (in
# parallel — they are independent subprocesses) and returns
# one merged, severity-sorted findings list. A missing or
# crashing scanner never breaks ingestion.
# =========================================================

from concurrent.futures import ThreadPoolExecutor

from backend.logging_setup import get_logger
from backend.scanners.base import SEVERITY_ORDER

logger = get_logger(__name__)
from backend.scanners import (
    gitleaks_scanner,
    checkov_scanner,
    trivy_scanner,
    hadolint_scanner,
    semgrep_scanner,
    kubesec_scanner,
    injection_scanner,
)

SCANNERS = [
    gitleaks_scanner,    # secrets
    checkov_scanner,     # IaC misconfigurations
    trivy_scanner,       # vulnerable dependencies (CVEs)
    hadolint_scanner,    # Dockerfile best practices
    semgrep_scanner,     # application code SAST
    kubesec_scanner,     # Kubernetes manifest risk
    injection_scanner,   # prompt-injection attempts (built-in)
]


def scanner_status() -> dict:
    """Availability of each registered scanner (for /health)."""
    return {s.TOOL: s.available() for s in SCANNERS}


def _run_one(scanner, workspace_dir):
    return scanner.TOOL, scanner.scan(workspace_dir)


def run_all_scanners(workspace_dir: str) -> dict:
    findings = []
    tools_run = []
    tools_missing = []

    runnable = []
    for scanner in SCANNERS:
        if scanner.available():
            runnable.append(scanner)
        else:
            tools_missing.append(scanner.TOOL)

    with ThreadPoolExecutor(max_workers=len(runnable) or 1) as pool:
        futures = {pool.submit(_run_one, s, workspace_dir): s for s in runnable}
        for future, scanner in futures.items():
            try:
                tool, tool_findings = future.result()
                findings.extend(tool_findings)
                tools_run.append(tool)
            except Exception as e:
                logger.error("scanner %s crashed: %s", scanner.TOOL, e)
                # A crashed scanner is a coverage gap — report it as
                # missing so the UI and the LLM's ground-truth section
                # surface it instead of silently dropping the tool.
                tools_missing.append(scanner.TOOL)

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["file"], f["line"]))

    logger.info("scan complete findings=%d ran=%s missing=%s",
                len(findings), tools_run or "none", tools_missing or "none")

    return {
        "findings": findings,
        "tools_run": tools_run,
        "tools_missing": tools_missing,
    }
