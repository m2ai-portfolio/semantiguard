"""Tests for the scan CLI command."""

import json
import os
import pytest
from click.testing import CliRunner
from pathlib import Path

from semantiguard.cli import cli
from semantiguard.db import init_db, seed_sample_data


@pytest.fixture
def test_db(tmp_path):
    """Create a test database with sample data."""
    db_path = tmp_path / "test_semantiguard.db"
    os.environ['SEMANTIGUARD_DB_PATH'] = str(db_path)
    init_db(str(db_path))
    seed_sample_data(str(db_path))
    yield db_path
    # Cleanup
    if 'SEMANTIGUARD_DB_PATH' in os.environ:
        del os.environ['SEMANTIGUARD_DB_PATH']


def test_cli_scan_table_with_findings(test_db, tmp_path):
    """Test scan command with table format and findings."""
    # Create test requirements.txt
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.28.1\nnumpy==1.24.3\n")

    runner = CliRunner()
    result = runner.invoke(cli, ['scan', str(req_file)])

    # Should exit with code 1 (vulnerabilities found)
    assert result.exit_code == 1

    # Check output contains expected elements
    assert "requests" in result.output
    assert "2.28.1" in result.output
    assert "CVE-2023-32681" in result.output
    assert "high" in result.output

    assert "numpy" in result.output
    assert "1.24.3" in result.output
    assert "CVE-2023-41105" in result.output

    # Check for table formatting
    assert "Package" in result.output
    assert "Version" in result.output
    assert "CVE ID" in result.output
    assert "Severity" in result.output

    # Check summary
    assert "Found" in result.output
    assert "vulnerabilities" in result.output


def test_cli_scan_table_no_findings(test_db, tmp_path):
    """Test scan command with table format and no findings."""
    # Create test requirements.txt with packages that have no CVEs
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("click==8.1.3\npandas==2.0.1\n")

    runner = CliRunner()
    result = runner.invoke(cli, ['scan', str(req_file)])

    # Should exit with code 0 (no vulnerabilities)
    assert result.exit_code == 0

    # Check output
    assert "No vulnerabilities found" in result.output


def test_cli_scan_json_with_findings(test_db, tmp_path):
    """Test scan command with JSON format and findings."""
    # Create test requirements.txt
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.28.1\nnumpy==1.24.3\n")

    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '--format', 'json', str(req_file)])

    # Should exit with code 1 (vulnerabilities found)
    assert result.exit_code == 1

    # Parse JSON output
    parsed = json.loads(result.output)

    # Check structure
    assert len(parsed) == 2

    # Find requests result
    requests_result = next((r for r in parsed if r['package'] == 'requests'), None)
    assert requests_result is not None
    assert requests_result['version'] == '2.28.1'
    assert len(requests_result['advisories']) == 2

    # Find numpy result
    numpy_result = next((r for r in parsed if r['package'] == 'numpy'), None)
    assert numpy_result is not None
    assert numpy_result['version'] == '1.24.3'
    assert len(numpy_result['advisories']) == 1


def test_cli_scan_json_no_findings(test_db, tmp_path):
    """Test scan command with JSON format and no findings."""
    # Create test requirements.txt with packages that have no CVEs
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("click==8.1.3\npandas==2.0.1\n")

    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '--format', 'json', str(req_file)])

    # Should exit with code 0 (no vulnerabilities)
    assert result.exit_code == 0

    # Parse JSON output
    parsed = json.loads(result.output)

    assert len(parsed) == 2
    assert all(len(r['advisories']) == 0 for r in parsed)


def test_cli_scan_exit_code_1_vulnerabilities(test_db, tmp_path):
    """Verify exit code 1 when vulnerabilities are found."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.28.1\n")

    runner = CliRunner()
    result = runner.invoke(cli, ['scan', str(req_file)])

    assert result.exit_code == 1


def test_cli_scan_exit_code_0_clean(test_db, tmp_path):
    """Verify exit code 0 when no vulnerabilities are found."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("click==8.1.3\n")

    runner = CliRunner()
    result = runner.invoke(cli, ['scan', str(req_file)])

    assert result.exit_code == 0


def test_cli_scan_missing_file(test_db):
    """Verify exit code 2 for missing file."""
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '/nonexistent/requirements.txt'])

    assert result.exit_code == 2
    assert "not found" in result.output.lower() or "error" in result.output.lower()


def test_cli_scan_no_database(tmp_path):
    """Test scan command when database doesn't exist."""
    # Ensure no database exists
    db_path = tmp_path / "nonexistent.db"
    os.environ['SEMANTIGUARD_DB_PATH'] = str(db_path)

    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.28.1\n")

    runner = CliRunner()
    result = runner.invoke(cli, ['scan', str(req_file)])

    # Should exit with code 2 (error)
    assert result.exit_code == 2
    assert "not initialized" in result.output.lower()

    # Cleanup
    if 'SEMANTIGUARD_DB_PATH' in os.environ:
        del os.environ['SEMANTIGUARD_DB_PATH']


def test_cli_scan_pyproject_toml(test_db, tmp_path):
    """Test scan command with pyproject.toml file."""
    # Create test pyproject.toml
    toml_file = tmp_path / "pyproject.toml"
    toml_file.write_text("""[project]
name = "test-project"
version = "0.1.0"
dependencies = [
    "requests>=2.28.1",
    "flask>=2.3.0",
]
""")

    runner = CliRunner()
    result = runner.invoke(cli, ['scan', str(toml_file)])

    # Should exit with code 1 (vulnerabilities found)
    assert result.exit_code == 1

    # Check output contains expected packages
    assert "requests" in result.output
    assert "flask" in result.output


def test_cli_scan_mixed_results(test_db, tmp_path):
    """Test scan with both vulnerable and clean packages."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.28.1\nclick==8.1.3\nnumpy==1.24.3\n")

    runner = CliRunner()
    result = runner.invoke(cli, ['scan', str(req_file)])

    # Should exit with code 1 (vulnerabilities found)
    assert result.exit_code == 1

    # Output should include vulnerable packages
    assert "requests" in result.output
    assert "numpy" in result.output

    # But not necessarily show clean packages in table format
    # (they'll be in JSON format though)
