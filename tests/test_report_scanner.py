# Structured import of uploaded Trivy/SARIF reports + SBOM detection.
# Fixes ING-01/02/03: previously these produced 0 findings (LLM-only).
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.scanners import report_scanner as rs
from backend import scanners


def _ws(files):
    d = tempfile.mkdtemp()
    for name, content in files.items():
        with open(os.path.join(d, name), "w") as f:
            f.write(content)
    return d


def test_trivy_json_imported_as_findings():
    trivy = json.dumps({"SchemaVersion": 2, "Results": [{"Target": "app", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j-core",
         "InstalledVersion": "2.14.1", "FixedVersion": "2.17.1",
         "Severity": "CRITICAL", "Title": "Log4Shell RCE"}]}]})
    fs = rs.scan(_ws({"trivy-report.json": trivy}))
    assert len(fs) == 1
    f = fs[0]
    assert f["severity"] == "CRITICAL"
    assert f["rule_id"] == "CVE-2021-44228"
    assert "log4j-core" in f["evidence"] and "2.17.1" in f["evidence"]
    assert "imported" in f["tool"]


def test_sarif_imported_as_findings():
    sarif = json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep"}},
        "results": [{"ruleId": "sql-injection", "level": "error",
                     "message": {"text": "SQL injection"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "app.py"},
                         "region": {"startLine": 10}}}]}]}]})
    fs = rs.scan(_ws({"results.sarif": sarif}))
    assert len(fs) == 1
    f = fs[0]
    assert f["severity"] == "HIGH"          # level error -> HIGH
    assert f["file"] == "app.py" and f["line"] == 10
    assert f["rule_id"] == "sql-injection"


def test_ordinary_json_is_not_a_report():
    fs = rs.scan(_ws({"package.json": json.dumps({"name": "app", "dependencies": {"x": "1"}})}))
    assert fs == []


def test_sbom_is_detected():
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "components": [{"type": "library", "name": "lodash", "version": "4.17.11"}]}
    spdx = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}
    assert rs._detect(cdx) == "cyclonedx"
    assert rs._detect(spdx) == "spdx"


def test_registered_and_available():
    assert rs.available() is True
    assert rs in scanners.SCANNERS
    assert scanners.scanner_status().get("report-import") is True
