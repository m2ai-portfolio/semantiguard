"""Tests for the CLI module."""

import json
from pathlib import Path
from click.testing import CliRunner

from semantiguard.cli import cli


def test_parse_command_requirements():
    """Test parse command with requirements.txt."""
    runner = CliRunner()
    test_file = Path(__file__).parent / "data" / "requirements.txt"

    result = runner.invoke(cli, ['parse', str(test_file)])

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert len(output) == 5
    assert output[0]['name'] == 'requests'
    assert output[0]['version'] == '2.28.1'


def test_parse_command_pyproject():
    """Test parse command with pyproject.toml."""
    runner = CliRunner()
    test_file = Path(__file__).parent / "data" / "pyproject.toml"

    result = runner.invoke(cli, ['parse', str(test_file)])

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert len(output) == 3
    assert output[0]['name'] == 'requests'
    assert output[0]['version'] == '2.28.1'


def test_parse_command_nonexistent_file():
    """Test parse command with non-existent file returns exit code 2."""
    runner = CliRunner()

    result = runner.invoke(cli, ['parse', 'nonexistent.txt'])

    assert result.exit_code == 2
    assert 'Error' in result.output
    assert 'not found' in result.output.lower()


def test_cli_version():
    """Test CLI version option."""
    runner = CliRunner()

    result = runner.invoke(cli, ['--version'])

    assert result.exit_code == 0
    assert '0.1.0' in result.output


def test_cli_help():
    """Test CLI help output."""
    runner = CliRunner()

    result = runner.invoke(cli, ['--help'])

    assert result.exit_code == 0
    assert 'SemantiGuard' in result.output


def test_parse_help():
    """Test parse command help output."""
    runner = CliRunner()

    result = runner.invoke(cli, ['parse', '--help'])

    assert result.exit_code == 0
    assert 'Parse a dependency manifest' in result.output
