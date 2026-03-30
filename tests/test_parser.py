"""Tests for the parser module."""

import pytest
from pathlib import Path

from semantiguard.parser import (
    parse_manifest,
    parse_requirements_txt,
    parse_pyproject_toml,
)
from semantiguard.models import Dependency


def test_parse_requirements_txt():
    """Test parsing requirements.txt correctly extracts packages."""
    test_file = Path(__file__).parent / "data" / "requirements.txt"
    dependencies = parse_requirements_txt(test_file)

    assert len(dependencies) == 5
    assert dependencies[0].name == "requests"
    assert dependencies[0].version == "2.28.1"
    assert dependencies[1].name == "numpy"
    assert dependencies[1].version == "1.24.3"
    assert dependencies[2].name == "pandas"
    assert dependencies[2].version == "2.0.1"
    assert dependencies[3].name == "click"
    assert dependencies[3].version == "8.1.3"
    assert dependencies[4].name == "pydantic"
    assert dependencies[4].version == "2.0.0"


def test_parse_pyproject_toml():
    """Test parsing pyproject.toml correctly extracts packages."""
    test_file = Path(__file__).parent / "data" / "pyproject.toml"
    dependencies = parse_pyproject_toml(test_file)

    assert len(dependencies) == 3
    assert dependencies[0].name == "requests"
    assert dependencies[0].version == "2.28.1"
    assert dependencies[1].name == "numpy"
    assert dependencies[1].version == "1.24.3"
    assert dependencies[2].name == "flask"
    assert dependencies[2].version == "2.3.0"


def test_parse_manifest_requirements():
    """Test parse_manifest with requirements.txt."""
    test_file = str(Path(__file__).parent / "data" / "requirements.txt")
    dependencies = parse_manifest(test_file)

    assert len(dependencies) == 5
    assert dependencies[0].name == "requests"


def test_parse_manifest_pyproject():
    """Test parse_manifest with pyproject.toml."""
    test_file = str(Path(__file__).parent / "data" / "pyproject.toml")
    dependencies = parse_manifest(test_file)

    assert len(dependencies) == 3
    assert dependencies[0].name == "requests"


def test_parse_manifest_missing_file():
    """Test handling of missing files."""
    with pytest.raises(FileNotFoundError):
        parse_manifest("nonexistent.txt")


def test_parse_requirements_with_comments(tmp_path):
    """Test handling of comments and empty lines in requirements.txt."""
    test_file = tmp_path / "requirements.txt"
    test_file.write_text("""
# This is a comment
requests==2.28.1

# Another comment
numpy==1.24.3
""")

    dependencies = parse_requirements_txt(test_file)
    assert len(dependencies) == 2
    assert dependencies[0].name == "requests"
    assert dependencies[1].name == "numpy"


def test_parse_empty_requirements(tmp_path):
    """Test handling of empty requirements.txt."""
    test_file = tmp_path / "requirements.txt"
    test_file.write_text("")

    dependencies = parse_requirements_txt(test_file)
    assert len(dependencies) == 0


def test_parse_empty_pyproject(tmp_path):
    """Test handling of empty pyproject.toml."""
    test_file = tmp_path / "pyproject.toml"
    test_file.write_text("[project]\nname = 'test'\n")

    dependencies = parse_pyproject_toml(test_file)
    assert len(dependencies) == 0
