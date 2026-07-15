import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.redaction import (
    clear_secrets,
    harvest_secrets,
    remember_secret,
    scrub_secrets,
)
from backend.scanners import gitleaks_scanner


@pytest.fixture(autouse=True)
def clean_registry():
    clear_secrets()
    yield
    clear_secrets()


def test_known_secret_is_masked_everywhere():
    remember_secret("wJalrXUtnFEMI/K7MDENG/bPxRCiCYzz9qLfake")
    text = 'The file contains secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRCiCYzz9qLfake" on line 8.'
    out = scrub_secrets(text)
    assert "wJalrXUtnFEMI/K7MDENG/bPxRCiCYzz9qLfake" not in out
    assert 'secret_key = "wJal****************" on line 8.' in out


def test_multiple_occurrences_all_masked():
    remember_secret("SuperSecret123!")
    out = scrub_secrets("SuperSecret123! appears twice: SuperSecret123!")
    assert "SuperSecret123!" not in out
    assert out.count("Supe" + "*" * 11) == 2


def test_pattern_fallback_without_registration():
    # Nothing registered — pattern matching still catches known formats
    out = scrub_secrets('access_key = "AKIAQWERTYU1OPASDF2G"')
    assert "AKIAQWERTYU1OPASDF2G" not in out
    assert "AKIA" + "*" * 16 in out

    out = scrub_secrets("token: ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in out


def test_private_key_block_redacted():
    text = (
        "Here is the key:\n-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\nDone."
    )
    out = scrub_secrets(text)
    assert "MIIEowIBAAKCAQEA" not in out
    assert "[REDACTED PRIVATE KEY]" in out


def test_short_and_empty_values_ignored():
    remember_secret("")
    remember_secret("abc")  # below minimum length — too risky to scrub
    assert scrub_secrets("abc is fine in prose") == "abc is fine in prose"
    assert scrub_secrets("") == ""


def test_harvest_secrets_from_file_content():
    content = '''
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAQWERTYU1OPASDF2G"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRCiCYzz9qLfake"
}
db_password: "hunter2hunter2"
'''
    harvest_secrets(content)
    out = scrub_secrets(
        "found wJalrXUtnFEMI/K7MDENG/bPxRCiCYzz9qLfake and hunter2hunter2"
    )
    assert "wJalrXUtnFEMI/K7MDENG/bPxRCiCYzz9qLfake" not in out
    assert "hunter2hunter2" not in out


def test_harvest_ignores_non_credential_assignments():
    harvest_secrets('image = "nginx:1.25.3"\nregion = "eu-central-1"')
    out = scrub_secrets("use nginx:1.25.3 in eu-central-1")
    assert "nginx:1.25.3" in out
    assert "eu-central-1" in out


def test_gitleaks_parse_registers_raw_secret():
    report = [{
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "File": "main.tf",
        "StartLine": 7,
        "Secret": "myRawSecretValue123",
    }]
    findings = gitleaks_scanner.parse_report(report, "")
    # Finding itself carries only the redacted form...
    assert "myRawSecretValue123" not in str(findings)
    # ...but the raw value is registered for output scrubbing
    assert "myRawSecretValue123" not in scrub_secrets(
        "the value is myRawSecretValue123"
    )
