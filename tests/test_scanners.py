import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.scanners import run_all_scanners
from backend.scanners.base import make_finding, redact_secret
from backend.scanners import (
    gitleaks_scanner,
    checkov_scanner,
    trivy_scanner,
    hadolint_scanner,
    semgrep_scanner,
    kubesec_scanner,
    shellcheck_scanner,
    actionlint_scanner,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable")


@pytest.fixture
def workspace_copy(tmp_path):
    """
    Fixtures copied outside tests/ — mirrors the production workspace
    dir and avoids semgrep's default ignore of tests/ directories.
    """
    import shutil
    dest = tmp_path / "workspace"
    shutil.copytree(FIXTURES, dest)
    return str(dest)


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
# TRIVY PARSER (no binary required)
# =========================================================

TRIVY_REPORT = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2017-18342",
                    "PkgName": "pyyaml",
                    "InstalledVersion": "3.12",
                    "FixedVersion": "4.1",
                    "Severity": "CRITICAL",
                    "Title": "yaml.load() API could execute arbitrary code",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-18342",
                },
                {
                    "VulnerabilityID": "CVE-0000-0001",
                    "PkgName": "leftpad",
                    "InstalledVersion": "1.0",
                    "Severity": "LOW",
                },
            ],
        }
    ]
}


def test_trivy_parse_report():
    findings = trivy_scanner.parse_report(TRIVY_REPORT)
    assert len(findings) == 2
    assert findings[0]["rule_id"] == "CVE-2017-18342"
    assert findings[0]["severity"] == "CRITICAL"
    assert "fix: upgrade to 4.1" in findings[0]["evidence"]
    assert "no fix released yet" in findings[1]["evidence"]


def test_trivy_parse_empty():
    assert trivy_scanner.parse_report({}) == []
    assert trivy_scanner.parse_report({"Results": [{"Target": "x"}]}) == []


# =========================================================
# HADOLINT PARSER (no binary required)
# =========================================================

HADOLINT_REPORT = [
    {"code": "DL3007", "message": "Using latest is prone to errors",
     "file": "ws/Dockerfile", "line": 2, "level": "warning"},
    {"code": "DL3002", "message": "Last USER should not be root",
     "file": "ws/Dockerfile", "line": 8, "level": "error"},
    {"code": "SC2046", "message": "Quote this", "file": "ws/Dockerfile",
     "line": 5, "level": "style"},
]


def test_hadolint_parse_report():
    findings = hadolint_scanner.parse_report(HADOLINT_REPORT, "ws")
    assert len(findings) == 3
    assert findings[0]["severity"] == "MEDIUM"   # warning
    assert findings[1]["severity"] == "HIGH"     # error
    assert findings[2]["severity"] == "LOW"      # style
    assert findings[0]["file"] == "Dockerfile"
    assert findings[0]["guideline"].endswith("DL3007")
    assert findings[2]["guideline"] is None      # SC codes have no wiki page


# =========================================================
# SEMGREP PARSER (no binary required)
# =========================================================

SEMGREP_REPORT = {
    "results": [
        {
            "check_id": "python.lang.security.audit.sql-injection",
            "path": "ws/app.py",
            "start": {"line": 12},
            "extra": {
                "severity": "ERROR",
                "message": "SQL injection via string concatenation",
                "lines": 'rows = conn.execute("SELECT ..." + user_id)',
                "metadata": {"references": ["https://owasp.org/sql-injection"]},
            },
        }
    ]
}


def test_semgrep_parse_report():
    findings = semgrep_scanner.parse_report(SEMGREP_REPORT, "ws")
    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "sql-injection"
    assert f["severity"] == "HIGH"
    assert f["file"] == "app.py"
    assert f["line"] == 12
    assert f["guideline"] == "https://owasp.org/sql-injection"


# =========================================================
# KUBESEC PARSER (no binary required)
# =========================================================

KUBESEC_REPORT = [
    {
        "object": "Deployment/web-app.default",
        "valid": True,
        "score": -30,
        "scoring": {
            "critical": [
                {"id": "Privileged", "selector": "containers[] .securityContext .privileged == true",
                 "reason": "Privileged containers can allow almost complete host access", "points": -30},
            ],
            "advise": [
                {"id": "ServiceAccountName", "selector": ".spec .serviceAccountName",
                 "reason": "Service accounts restrict API access"},
            ],
        },
    },
    {"object": "invalid", "valid": False},
]


def test_kubesec_parse_report():
    findings = kubesec_scanner.parse_report(KUBESEC_REPORT, "deployment.yaml")
    assert len(findings) == 2
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["rule_id"] == "Privileged"
    assert findings[1]["severity"] == "LOW"
    assert all(f["file"] == "deployment.yaml" for f in findings)


# =========================================================
# SHELLCHECK PARSER (no binary required)
# =========================================================

SHELLCHECK_REPORT = [
    {"file": "/ws/deploy.sh", "line": 3, "column": 8, "level": "warning",
     "code": 2115, "message": "Use \"${var:?}\" to ensure this never expands to /*."},
    {"file": "/ws/deploy.sh", "line": 3, "column": 8, "level": "info",
     "code": 2086, "message": "Double quote to prevent globbing and word splitting."},
    {"file": "/ws/deploy.sh", "line": 4, "column": 1, "level": "error",
     "code": 2239, "message": "Ensure the shebang uses an absolute path."},
]


def test_shellcheck_parse_report():
    from backend.scanners import shellcheck_scanner
    findings = shellcheck_scanner.parse_report(SHELLCHECK_REPORT, "/ws")
    assert len(findings) == 3
    assert findings[0]["rule_id"] == "SC2115" and findings[0]["severity"] == "MEDIUM"
    assert findings[1]["severity"] == "LOW"           # info -> LOW
    assert findings[2]["severity"] == "HIGH"          # error -> HIGH
    assert all(f["file"] == "deploy.sh" for f in findings)  # relpath
    assert findings[0]["guideline"].endswith("SC2115")


def test_shellcheck_parse_empty():
    from backend.scanners import shellcheck_scanner
    assert shellcheck_scanner.parse_report([], "/ws") == []
    assert shellcheck_scanner.parse_report(None, "/ws") == []


# =========================================================
# ACTIONLINT PARSER (no binary required)
# =========================================================

ACTIONLINT_REPORT = [
    {"message": "\"github.event.pull_request.title\" is potentially untrusted. avoid using it directly",
     "filepath": "/ws/.github/workflows/ci.yml", "line": 9, "column": 24, "kind": "expression"},
    {"message": "shellcheck reported issue in this script: SC2086:info",
     "filepath": "/ws/.github/workflows/ci.yml", "line": 10, "column": 9, "kind": "shellcheck"},
]


def test_actionlint_parse_report():
    from backend.scanners import actionlint_scanner
    findings = actionlint_scanner.parse_report(ACTIONLINT_REPORT, "/ws")
    assert len(findings) == 2
    # script injection (untrusted expression) must be HIGH
    assert findings[0]["severity"] == "HIGH" and findings[0]["rule_id"] == "expression"
    assert findings[1]["severity"] == "MEDIUM"
    assert all(f["file"] == ".github/workflows/ci.yml" for f in findings)  # relpath


def test_actionlint_parse_empty():
    from backend.scanners import actionlint_scanner
    assert actionlint_scanner.parse_report([], "/ws") == []
    assert actionlint_scanner.parse_report(None, "/ws") == []


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


@pytest.mark.skipif(not trivy_scanner.available(), reason="trivy not installed")
def test_trivy_finds_fixture_cves(workspace_copy):
    findings = trivy_scanner.scan(workspace_copy)
    assert any(f["rule_id"].startswith("CVE-") for f in findings)
    assert any("pyyaml" in f["title"] for f in findings)


@pytest.mark.skipif(not hadolint_scanner.available(), reason="hadolint not installed")
def test_hadolint_finds_fixture_issues(workspace_copy):
    findings = hadolint_scanner.scan(workspace_copy)
    rule_ids = {f["rule_id"] for f in findings}
    assert "DL3007" in rule_ids  # latest tag
    assert "DL3002" in rule_ids  # root user


@pytest.mark.skipif(not semgrep_scanner.available(), reason="semgrep not installed")
def test_semgrep_finds_fixture_injections(workspace_copy):
    findings = semgrep_scanner.scan(workspace_copy)
    assert any("sql" in f["rule_id"].lower() for f in findings)
    assert any(f["file"].endswith("app.py") for f in findings)


@pytest.mark.skipif(not kubesec_scanner.available(), reason="kubesec not installed")
def test_kubesec_finds_privileged_container(workspace_copy):
    findings = kubesec_scanner.scan(workspace_copy)
    assert any(f["rule_id"] == "Privileged" and f["severity"] == "HIGH" for f in findings)


@pytest.mark.skipif(not shellcheck_scanner.available(), reason="shellcheck not installed")
def test_shellcheck_finds_fixture_issues(workspace_copy):
    findings = shellcheck_scanner.scan(workspace_copy)
    assert any(f["rule_id"].startswith("SC") for f in findings)


@pytest.mark.skipif(not actionlint_scanner.available(), reason="actionlint not installed")
def test_actionlint_finds_workflow_injection(workspace_copy):
    findings = actionlint_scanner.scan(workspace_copy)
    assert any(f["severity"] == "HIGH" and f["rule_id"] == "expression" for f in findings)


@pytest.mark.skipif(
    not (gitleaks_scanner.available() and checkov_scanner.available()),
    reason="scanners not installed",
)
def test_run_all_scanners_merges_and_sorts(workspace_copy):
    result = run_all_scanners(workspace_copy)
    assert "gitleaks" in result["tools_run"]
    assert "checkov" in result["tools_run"]
    sevs = [f["severity"] for f in result["findings"]]
    # CRITICAL findings must sort before MEDIUM
    assert sevs.index("CRITICAL") < sevs.index("MEDIUM")
