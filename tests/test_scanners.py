import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.scanners import run_all_scanners
from backend.scanners.base import make_finding, redact_secret
from backend.scanners import gitleaks_scanner, checkov_scanner

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable")


# =========================================================
# BASE HELPERS
# =========================================================

def test_redact_secret_keeps_prefix_only():
    assert redact_secret("AKIAQWERTYU1OPASDF2G") == "AKIA" + "*" * 16
    assert "QWERTYU1OPASDF2G" not in redact_secret("AKIAQWERTYU1OPASDF2G")


def test_redact_secret_short_and_empty():
    assert redact_secret("") == ""
    assert redact_secret("abc") == "***"


def test_make_finding_normalizes_unknown_severity():
    f = make_finding("t", "r", "BOGUS", "f", 1, "title")
    assert f["severity"] == "MEDIUM"
    f = make_finding("t", "r", None, "f", 1, "title")
    assert f["severity"] == "MEDIUM"
    f = make_finding("t", "r", "critical", "f", 1, "title")
    assert f["severity"] == "CRITICAL"


# =========================================================
# GITLEAKS PARSER (no binary required)
# =========================================================

GITLEAKS_REPORT = [
    {
        "RuleID": "aws-access-key-id",
        "Description": "AWS Access Key ID",
        "File": "workspace/proj/main.tf",
        "StartLine": 7,
        "Secret": "AKIAQWERTYU1OPASDF2G",
        "Match": "access_key = AKIAQWERTYU1OPASDF2G",
    }
]


def test_gitleaks_parse_report():
    findings = gitleaks_scanner.parse_report(GITLEAKS_REPORT, "workspace")
    assert len(findings) == 1
    f = findings[0]
    assert f["tool"] == "gitleaks"
    assert f["severity"] == "CRITICAL"
    assert f["file"] == "proj/main.tf"
    assert f["line"] == 7
    # The raw secret must never appear in the finding
    assert "AKIAQWERTYU1OPASDF2G" not in str(f)
    assert f["evidence"].startswith("AKIA")


def test_gitleaks_parse_empty_report():
    assert gitleaks_scanner.parse_report([], "workspace") == []
    assert gitleaks_scanner.parse_report(None, "workspace") == []


# =========================================================
# CHECKOV PARSER (no binary required)
# =========================================================

CHECKOV_REPORT = {
    "check_type": "terraform",
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_AWS_24",
                "check_name": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
                "file_path": "/main.tf",
                "file_line_range": [11, 19],
                "resource": "aws_security_group.web",
                "severity": None,
                "guideline": "https://docs.example/ckv-aws-24",
            },
            {
                "check_id": "CKV_AWS_20",
                "check_name": "S3 bucket public read",
                "file_path": "/main.tf",
                "file_line_range": [22, 25],
                "resource": "aws_s3_bucket.data",
                "severity": "HIGH",
                "guideline": None,
            },
        ]
    },
}


def test_checkov_parse_single_block():
    findings = checkov_scanner.parse_report(CHECKOV_REPORT)
    assert len(findings) == 2
    assert findings[0]["file"] == "main.tf"
    assert findings[0]["line"] == 11
    assert findings[0]["severity"] == "MEDIUM"  # null severity defaults
    assert findings[0]["guideline"] == "https://docs.example/ckv-aws-24"
    assert findings[1]["severity"] == "HIGH"  # real severity kept


def test_checkov_parse_multi_framework_list():
    findings = checkov_scanner.parse_report([CHECKOV_REPORT, CHECKOV_REPORT])
    assert len(findings) == 4


def test_checkov_parse_empty_and_malformed():
    assert checkov_scanner.parse_report({}) == []
    assert checkov_scanner.parse_report([{"results": {}}]) == []
    assert checkov_scanner.parse_report(["not-a-dict"]) == []


# =========================================================
# INTEGRATION — requires real scanners on PATH
# =========================================================

@pytest.mark.skipif(not gitleaks_scanner.available(), reason="gitleaks not installed")
def test_gitleaks_finds_fixture_secret():
    findings = gitleaks_scanner.scan(FIXTURES)
    assert any(f["file"].endswith("main.tf") for f in findings)
    assert all("AKIAQWERTYU1OPASDF2G" not in str(f) for f in findings)


@pytest.mark.skipif(not checkov_scanner.available(), reason="checkov not installed")
def test_checkov_finds_fixture_misconfigs():
    findings = checkov_scanner.scan(FIXTURES)
    rule_ids = {f["rule_id"] for f in findings}
    assert "CKV_AWS_24" in rule_ids      # open SSH ingress
    assert "CKV_DOCKER_8" in rule_ids    # root user


@pytest.mark.skipif(
    not (gitleaks_scanner.available() and checkov_scanner.available()),
    reason="scanners not installed",
)
def test_run_all_scanners_merges_and_sorts():
    result = run_all_scanners(FIXTURES)
    assert set(result["tools_run"]) == {"gitleaks", "checkov"}
    assert result["tools_missing"] == []
    sevs = [f["severity"] for f in result["findings"]]
    # CRITICAL findings must sort before MEDIUM
    assert sevs.index("CRITICAL") < sevs.index("MEDIUM")
