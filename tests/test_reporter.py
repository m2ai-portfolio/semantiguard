"""Tests for the reporter module."""

import json
import pytest

from semantiguard.models import ScanResult, Advisory
from semantiguard.reporter import format_table, format_json, has_findings


def test_format_table_with_findings():
    """Test table formatting with vulnerabilities."""
    scan_results = [
        ScanResult(
            package="requests",
            version="2.28.1",
            advisories=[
                Advisory(cve_id="CVE-2023-32681", severity="high", description="Unintended leak of Proxy-Authorization header"),
                Advisory(cve_id="CVE-2023-45803", severity="medium", description="Cookie handling vulnerability"),
            ]
        ),
        ScanResult(
            package="numpy",
            version="1.24.3",
            advisories=[
                Advisory(cve_id="CVE-2023-41105", severity="medium", description="Path traversal in numpy.load"),
            ]
        ),
    ]

    output = format_table(scan_results)

    # Check that output contains expected elements
    assert "requests" in output
    assert "2.28.1" in output
    assert "CVE-2023-32681" in output
    assert "high" in output
    assert "Unintended leak" in output

    assert "numpy" in output
    assert "1.24.3" in output
    assert "CVE-2023-41105" in output
    assert "medium" in output

    # Check summary line
    assert "Found 3 vulnerabilities in 2 packages" in output

    # Check table structure
    assert "Package" in output
    assert "Version" in output
    assert "CVE ID" in output
    assert "Severity" in output
    assert "Description" in output


def test_format_table_no_findings():
    """Test table formatting with no vulnerabilities."""
    scan_results = [
        ScanResult(package="click", version="8.1.3", advisories=[]),
        ScanResult(package="pandas", version="2.0.1", advisories=[]),
    ]

    output = format_table(scan_results)

    assert output == "No vulnerabilities found."


def test_format_table_long_description():
    """Test table formatting with long descriptions that need truncation."""
    scan_results = [
        ScanResult(
            package="test-package",
            version="1.0.0",
            advisories=[
                Advisory(
                    cve_id="CVE-2024-00000",
                    severity="critical",
                    description="A" * 100  # Very long description
                ),
            ]
        ),
    ]

    output = format_table(scan_results)

    # Check that description is truncated with ellipsis
    assert "..." in output
    # Ensure the full description is not present
    assert "A" * 100 not in output


def test_format_json_with_findings():
    """Test JSON formatting with vulnerabilities."""
    scan_results = [
        ScanResult(
            package="requests",
            version="2.28.1",
            advisories=[
                Advisory(cve_id="CVE-2023-32681", severity="high", description="Leak"),
            ]
        ),
        ScanResult(
            package="numpy",
            version="1.24.3",
            advisories=[
                Advisory(cve_id="CVE-2023-41105", severity="medium", description="Path traversal"),
            ]
        ),
    ]

    output = format_json(scan_results)

    # Parse JSON to validate it
    parsed = json.loads(output)

    assert len(parsed) == 2
    assert parsed[0]["package"] == "requests"
    assert parsed[0]["version"] == "2.28.1"
    assert len(parsed[0]["advisories"]) == 1
    assert parsed[0]["advisories"][0]["cve_id"] == "CVE-2023-32681"
    assert parsed[0]["advisories"][0]["severity"] == "high"

    assert parsed[1]["package"] == "numpy"
    assert parsed[1]["version"] == "1.24.3"
    assert len(parsed[1]["advisories"]) == 1


def test_format_json_no_findings():
    """Test JSON formatting with no vulnerabilities."""
    scan_results = [
        ScanResult(package="click", version="8.1.3", advisories=[]),
        ScanResult(package="pandas", version="2.0.1", advisories=[]),
    ]

    output = format_json(scan_results)

    # Parse JSON to validate it
    parsed = json.loads(output)

    assert len(parsed) == 2
    assert parsed[0]["package"] == "click"
    assert len(parsed[0]["advisories"]) == 0
    assert parsed[1]["package"] == "pandas"
    assert len(parsed[1]["advisories"]) == 0


def test_has_findings_true():
    """Test has_findings with vulnerabilities."""
    scan_results = [
        ScanResult(
            package="requests",
            version="2.28.1",
            advisories=[
                Advisory(cve_id="CVE-2023-32681", severity="high", description="Leak"),
            ]
        ),
    ]

    assert has_findings(scan_results) is True


def test_has_findings_false():
    """Test has_findings with no vulnerabilities."""
    scan_results = [
        ScanResult(package="click", version="8.1.3", advisories=[]),
        ScanResult(package="pandas", version="2.0.1", advisories=[]),
    ]

    assert has_findings(scan_results) is False


def test_has_findings_empty_list():
    """Test has_findings with empty list."""
    assert has_findings([]) is False


def test_format_json_none_description():
    """Test JSON formatting with None description."""
    scan_results = [
        ScanResult(
            package="test",
            version="1.0.0",
            advisories=[
                Advisory(cve_id="CVE-2024-00000", severity="low", description=None),
            ]
        ),
    ]

    output = format_json(scan_results)
    parsed = json.loads(output)

    assert parsed[0]["advisories"][0]["description"] is None
