import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evals")
)

from run_benchmark import BENCHMARKS, finding_matches, score_canaries


def _finding(tool="checkov", rule_id="CKV_AWS_24", severity="MEDIUM"):
    return {"tool": tool, "rule_id": rule_id, "severity": severity,
            "file": "main.tf", "line": 1, "title": "t", "detail": "",
            "evidence": "", "guideline": None}


def test_exact_rule_match():
    canary = {"id": "x", "tool": "checkov", "rule": "CKV_AWS_24"}
    assert finding_matches(_finding(), canary)
    assert not finding_matches(_finding(rule_id="CKV_AWS_25"), canary)
    assert not finding_matches(_finding(tool="trivy"), canary)


def test_prefix_and_wildcard_rule_match():
    prefix = {"id": "x", "tool": "checkov", "rule": "CKV_SECRET_*"}
    assert finding_matches(_finding(rule_id="CKV_SECRET_2"), prefix)
    assert not finding_matches(_finding(rule_id="CKV_AWS_2"), prefix)

    wildcard = {"id": "x", "tool": "gitleaks", "rule": "*"}
    assert finding_matches(_finding(tool="gitleaks", rule_id="anything"), wildcard)


def test_severity_filter():
    canary = {"id": "x", "tool": "trivy", "rule": "*", "severity": "CRITICAL"}
    assert finding_matches(_finding(tool="trivy", severity="CRITICAL"), canary)
    assert not finding_matches(_finding(tool="trivy", severity="HIGH"), canary)


def test_score_canaries_min_count():
    findings = [_finding(tool="hadolint", rule_id=f"DL{i}") for i in range(5)]
    results = score_canaries(findings, [
        {"id": "enough", "tool": "hadolint", "rule": "*", "min": 5},
        {"id": "not-enough", "tool": "hadolint", "rule": "*", "min": 6},
        {"id": "absent", "tool": "kubesec", "rule": "*"},
    ])
    assert [r["detected"] for r in results] == [True, False, False]
    assert results[0]["hits"] == 5


def test_benchmark_definitions_are_well_formed():
    assert len(BENCHMARKS) == 3
    for b in BENCHMARKS:
        assert len(b["sha"]) == 40, "benchmarks must be pinned to full SHAs"
        assert b["canaries"], "every benchmark needs canaries"
        for c in b["canaries"]:
            assert {"id", "tool", "rule"} <= set(c)
