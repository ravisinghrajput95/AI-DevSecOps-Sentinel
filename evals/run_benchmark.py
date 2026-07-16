#!/usr/bin/env python3
# =========================================================
# DETECTION BENCHMARK
# Scores the scanner pipeline against deliberately vulnerable
# repositories pinned to specific commits. Each benchmark
# defines CANARIES — documented, planted vulnerabilities the
# pipeline is expected to detect. Scanner-only: no LLM or
# embedding calls, so running this costs nothing.
#
#   python evals/run_benchmark.py            # run + write RESULTS.md
#   python evals/run_benchmark.py --repo terragoat
#
# Exits non-zero if any canary is missed (CI-friendly).
# =========================================================

import argparse
import io
import os
import shutil
import sys
import tempfile
import time
import zipfile
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from backend.scanners import run_all_scanners

# =========================================================
# BENCHMARK DEFINITIONS
# Canary matchers: tool + rule (exact, or prefix with '*'),
# optional severity, optional min count (default 1).
# =========================================================

BENCHMARKS = [
    {
        "owner": "bridgecrewio",
        "repo": "terragoat",
        "sha": "729f8da62c6a85ce4af5ad3d123de97776d954c4",
        "description": "Vulnerable-by-design Terraform (AWS/Azure/GCP)",
        "canaries": [
            {"id": "hardcoded-cloud-credentials", "tool": "gitleaks", "rule": "*"},
            {"id": "secrets-in-iac", "tool": "checkov", "rule": "CKV_SECRET_*"},
            {"id": "ssh-open-to-world", "tool": "checkov", "rule": "CKV_AWS_24"},
            {"id": "unencrypted-ebs-volume", "tool": "checkov", "rule": "CKV_AWS_3"},
            {"id": "hardcoded-provider-credentials", "tool": "checkov", "rule": "CKV_AWS_41"},
            {"id": "unencrypted-launch-config-storage", "tool": "checkov", "rule": "CKV_AWS_8"},
            {"id": "critical-dependency-cve", "tool": "trivy", "rule": "*", "severity": "CRITICAL"},
            {"id": "ci-mutable-action-tags", "tool": "semgrep", "rule": "github-actions-mutable-action-tag"},
        ],
    },
    {
        "owner": "bridgecrewio",
        "repo": "cfngoat",
        "sha": "0c09b69cfc3dbc6cb3ef01883415c35c588ced48",
        "description": "Vulnerable-by-design CloudFormation",
        "canaries": [
            {"id": "hardcoded-aws-access-key", "tool": "gitleaks", "rule": "aws-access-token"},
            {"id": "sast-detects-aws-key", "tool": "semgrep", "rule": "detected-aws-access-key-id-value"},
            {"id": "ssh-open-to-world", "tool": "checkov", "rule": "CKV_AWS_24"},
            {"id": "s3-missing-public-access-block", "tool": "checkov", "rule": "CKV_AWS_53"},
            {"id": "iam-policy-issues", "tool": "checkov", "rule": "CKV_AWS_111"},
            {"id": "secrets-in-template", "tool": "checkov", "rule": "CKV_SECRET_*"},
        ],
    },
    {
        "owner": "madhuakula",
        "repo": "kubernetes-goat",
        "sha": "723a0db478f050d173d23b4ce5044b65bce0bdd0",
        "description": "Vulnerable-by-design Kubernetes environment",
        "canaries": [
            {"id": "privileged-container-kubesec", "tool": "kubesec", "rule": "Privileged"},
            {"id": "privileged-container-checkov", "tool": "checkov", "rule": "CKV_K8S_16"},
            {"id": "privilege-escalation-allowed", "tool": "checkov", "rule": "CKV_K8S_20"},
            {"id": "containers-run-as-root", "tool": "checkov", "rule": "CKV_K8S_23"},
            {"id": "dockerfile-missing-user", "tool": "semgrep", "rule": "missing-user"},
            {"id": "missing-resource-limits", "tool": "checkov", "rule": "CKV_K8S_10"},
            {"id": "hardcoded-secrets", "tool": "gitleaks", "rule": "*"},
            {"id": "dockerfile-best-practices", "tool": "hadolint", "rule": "*", "min": 10},
            {"id": "vulnerable-dependencies", "tool": "trivy", "rule": "*", "min": 10},
        ],
    },
]

RESULTS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RESULTS.md")


# =========================================================
# CANARY MATCHING
# =========================================================

def finding_matches(finding: dict, canary: dict) -> bool:
    if finding["tool"] != canary["tool"]:
        return False
    rule = canary["rule"]
    if rule != "*":
        if rule.endswith("*"):
            if not finding["rule_id"].startswith(rule[:-1]):
                return False
        elif finding["rule_id"] != rule:
            return False
    if "severity" in canary and finding["severity"] != canary["severity"]:
        return False
    return True


def score_canaries(findings: list, canaries: list) -> list:
    results = []
    for canary in canaries:
        hits = sum(1 for f in findings if finding_matches(f, canary))
        results.append({
            "id": canary["id"],
            "expected": canary.get("min", 1),
            "hits": hits,
            "detected": hits >= canary.get("min", 1),
        })
    return results


# =========================================================
# BENCHMARK EXECUTION
# =========================================================

def download_and_extract(owner: str, repo: str, sha: str) -> str:
    url = f"https://codeload.github.com/{owner}/{repo}/zip/{sha}"
    response = requests.get(url, timeout=120)
    response.raise_for_status()

    tmp = tempfile.mkdtemp(prefix=f"eval-{repo}-")
    with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
        zf.extractall(tmp)
    entries = os.listdir(tmp)
    if len(entries) == 1 and os.path.isdir(os.path.join(tmp, entries[0])):
        return os.path.join(tmp, entries[0])
    return tmp


def run_benchmark(benchmark: dict) -> dict:
    name = f"{benchmark['owner']}/{benchmark['repo']}"
    print(f"\n=== {name} @ {benchmark['sha'][:7]} ===")
    path = download_and_extract(
        benchmark["owner"], benchmark["repo"], benchmark["sha"]
    )
    try:
        started = time.time()
        scan = run_all_scanners(path)
        duration = time.time() - started
    finally:
        shutil.rmtree(os.path.dirname(path) if path.endswith(benchmark["sha"]) else path,
                      ignore_errors=True)

    findings = scan["findings"]
    canary_results = score_canaries(findings, benchmark["canaries"])
    detected = sum(1 for c in canary_results if c["detected"])

    by_tool = {}
    by_severity = {}
    for f in findings:
        by_tool[f["tool"]] = by_tool.get(f["tool"], 0) + 1
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    for c in canary_results:
        mark = "PASS" if c["detected"] else "MISS"
        print(f"  [{mark}] {c['id']}  ({c['hits']} hits, expected >= {c['expected']})")
    print(f"  canaries: {detected}/{len(canary_results)} | "
          f"findings: {len(findings)} | {duration:.0f}s")

    return {
        "name": name,
        "sha": benchmark["sha"],
        "description": benchmark["description"],
        "canaries": canary_results,
        "detected": detected,
        "total_canaries": len(canary_results),
        "findings": len(findings),
        "by_tool": by_tool,
        "by_severity": by_severity,
        "tools_missing": scan["tools_missing"],
        "duration": duration,
    }


# =========================================================
# REPORT
# =========================================================

def render_markdown(results: list) -> str:
    lines = [
        "# Detection Benchmark Results",
        "",
        f"Generated {date.today().isoformat()} by `evals/run_benchmark.py` — "
        "deterministic scanner pipeline only (no LLM), repositories pinned to commits.",
        "",
        "| Benchmark | Canaries detected | Findings | Scan time |",
        "|---|---|---|---|",
    ]
    for r in results:
        tools = ", ".join(f"{t} {n}" for t, n in sorted(r["by_tool"].items(), key=lambda x: -x[1]))
        lines.append(
            f"| [{r['name']}](https://github.com/{r['name']}/tree/{r['sha'][:7]}) "
            f"| **{r['detected']}/{r['total_canaries']}** "
            f"| {r['findings']} ({tools}) "
            f"| {r['duration']:.0f}s |"
        )

    for r in results:
        lines += [
            "",
            f"## {r['name']} — {r['description']}",
            "",
            "| Canary (documented planted issue) | Hits | Status |",
            "|---|---|---|",
        ]
        for c in r["canaries"]:
            status = "✅ detected" if c["detected"] else "❌ missed"
            lines.append(f"| `{c['id']}` | {c['hits']} | {status} |")

    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Run the detection benchmark")
    parser.add_argument("--repo", help="run a single benchmark by repo name")
    args = parser.parse_args()

    selected = [
        b for b in BENCHMARKS
        if not args.repo or b["repo"] == args.repo
    ]
    if not selected:
        print(f"No benchmark named '{args.repo}'. "
              f"Available: {', '.join(b['repo'] for b in BENCHMARKS)}")
        return 2

    results = [run_benchmark(b) for b in selected]

    if not args.repo:
        with open(RESULTS_PATH, "w") as f:
            f.write(render_markdown(results))
        print(f"\nReport written to {RESULTS_PATH}")

    missing_tools = set().union(*(r["tools_missing"] for r in results))
    if missing_tools:
        print(f"WARNING: scanners unavailable, results incomplete: {sorted(missing_tools)}")

    missed = [
        (r["name"], c["id"])
        for r in results for c in r["canaries"] if not c["detected"]
    ]
    if missed:
        print("\nMISSED CANARIES:")
        for name, canary in missed:
            print(f"  {name}: {canary}")
        return 1

    total = sum(r["total_canaries"] for r in results)
    print(f"\nAll {total} canaries detected across {len(results)} benchmarks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
