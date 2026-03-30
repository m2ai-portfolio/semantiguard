"""Tests for the database module."""

import json
import os
import sqlite3
from pathlib import Path
from click.testing import CliRunner

from semantiguard.db import (
    get_db_path,
    init_db,
    seed_sample_data,
    lookup_advisories,
    upsert_advisory,
    SAMPLE_ADVISORIES
)
from semantiguard.cli import cli


def test_init_db(tmp_path):
    """Test that init_db creates database file with correct schema."""
    db_path = tmp_path / "test.db"

    init_db(str(db_path))

    assert db_path.exists()

    # Verify schema
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Check table exists
    cursor.execute("""
        SELECT name FROM sqlite_master
        WHERE type='table' AND name='advisories'
    """)
    assert cursor.fetchone() is not None

    # Check indexes exist
    cursor.execute("""
        SELECT name FROM sqlite_master
        WHERE type='index' AND name='idx_advisories_package'
    """)
    assert cursor.fetchone() is not None

    cursor.execute("""
        SELECT name FROM sqlite_master
        WHERE type='index' AND name='idx_advisories_cve'
    """)
    assert cursor.fetchone() is not None

    conn.close()


def test_seed_data(tmp_path):
    """Test that seed_sample_data inserts sample advisories."""
    db_path = tmp_path / "test.db"

    init_db(str(db_path))
    seed_sample_data(str(db_path))

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM advisories")
    count = cursor.fetchone()[0]

    assert count == len(SAMPLE_ADVISORIES)

    # Verify a specific advisory
    cursor.execute("""
        SELECT cve_id, package_name, affected_version, severity, description
        FROM advisories
        WHERE cve_id = 'CVE-2023-32681'
    """)
    row = cursor.fetchone()

    assert row is not None
    assert row[0] == 'CVE-2023-32681'
    assert row[1] == 'requests'
    assert row[2] == '2.28.1'
    assert row[3] == 'high'

    conn.close()


def test_lookup_existing(tmp_path):
    """Test lookup_advisories returns matching advisories for known packages."""
    db_path = tmp_path / "test.db"

    init_db(str(db_path))
    seed_sample_data(str(db_path))

    # Lookup requests 2.28.1 - should have 2 advisories
    results = lookup_advisories('requests', '2.28.1', str(db_path))

    assert len(results) == 2
    assert results[0]['cve_id'] == 'CVE-2023-32681'  # high severity first
    assert results[0]['package_name'] == 'requests'
    assert results[0]['affected_version'] == '2.28.1'
    assert results[0]['severity'] == 'high'
    assert results[1]['cve_id'] == 'CVE-2023-45803'  # medium severity second
    assert results[1]['severity'] == 'medium'


def test_lookup_nonexistent(tmp_path):
    """Test lookup_advisories returns empty list for unknown packages."""
    db_path = tmp_path / "test.db"

    init_db(str(db_path))
    seed_sample_data(str(db_path))

    # Lookup package that doesn't exist
    results = lookup_advisories('unknown-package', '1.0.0', str(db_path))

    assert results == []


def test_lookup_nonexistent_db(tmp_path):
    """Test lookup_advisories returns empty list when DB doesn't exist."""
    db_path = tmp_path / "nonexistent.db"

    results = lookup_advisories('requests', '2.28.1', str(db_path))

    assert results == []


def test_upsert_insert(tmp_path):
    """Test upsert_advisory inserts new advisories correctly."""
    db_path = tmp_path / "test.db"

    init_db(str(db_path))

    # Insert new advisory
    upsert_advisory(
        'CVE-2024-12345',
        'test-package',
        '1.0.0',
        'critical',
        'Test vulnerability',
        str(db_path)
    )

    # Verify it was inserted
    results = lookup_advisories('test-package', '1.0.0', str(db_path))

    assert len(results) == 1
    assert results[0]['cve_id'] == 'CVE-2024-12345'
    assert results[0]['package_name'] == 'test-package'
    assert results[0]['severity'] == 'critical'
    assert results[0]['description'] == 'Test vulnerability'


def test_upsert_replace(tmp_path):
    """Test upsert_advisory replaces existing advisories correctly."""
    db_path = tmp_path / "test.db"

    init_db(str(db_path))

    # Insert initial advisory
    upsert_advisory(
        'CVE-2024-12345',
        'test-package',
        '1.0.0',
        'medium',
        'Original description',
        str(db_path)
    )

    # Update with same CVE ID
    upsert_advisory(
        'CVE-2024-12345',
        'test-package',
        '1.0.0',
        'critical',
        'Updated description',
        str(db_path)
    )

    # Verify it was updated (not duplicated)
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM advisories WHERE cve_id = 'CVE-2024-12345'")
    count = cursor.fetchone()[0]
    assert count == 1

    cursor.execute("""
        SELECT severity, description FROM advisories WHERE cve_id = 'CVE-2024-12345'
    """)
    row = cursor.fetchone()
    assert row[0] == 'critical'
    assert row[1] == 'Updated description'

    conn.close()


def test_cli_init_db(tmp_path, monkeypatch):
    """Test CLI init-db command."""
    db_path = tmp_path / "cli_test.db"
    monkeypatch.setenv('SEMANTIGUARD_DB_PATH', str(db_path))

    runner = CliRunner()
    result = runner.invoke(cli, ['init-db'])

    assert result.exit_code == 0
    assert 'DB initialized' in result.output
    assert db_path.exists()

    # Verify data was seeded
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM advisories")
    count = cursor.fetchone()[0]
    assert count == len(SAMPLE_ADVISORIES)
    conn.close()


def test_cli_lookup(tmp_path, monkeypatch):
    """Test CLI lookup command."""
    db_path = tmp_path / "cli_test.db"
    monkeypatch.setenv('SEMANTIGUARD_DB_PATH', str(db_path))

    # Initialize database first
    init_db(str(db_path))
    seed_sample_data(str(db_path))

    runner = CliRunner()
    result = runner.invoke(cli, ['lookup', '--package', 'requests', '--version', '2.28.1'])

    assert result.exit_code == 0

    # Parse JSON output
    advisories = json.loads(result.output)
    assert len(advisories) == 2
    assert advisories[0]['cve_id'] == 'CVE-2023-32681'
    assert advisories[0]['package_name'] == 'requests'


def test_cli_lookup_nonexistent(tmp_path, monkeypatch):
    """Test CLI lookup command with nonexistent package."""
    db_path = tmp_path / "cli_test.db"
    monkeypatch.setenv('SEMANTIGUARD_DB_PATH', str(db_path))

    # Initialize database first
    init_db(str(db_path))
    seed_sample_data(str(db_path))

    runner = CliRunner()
    result = runner.invoke(cli, ['lookup', '--package', 'unknown-pkg', '--version', '1.0.0'])

    assert result.exit_code == 0

    # Parse JSON output - should be empty array
    advisories = json.loads(result.output)
    assert advisories == []


def test_db_path_env(tmp_path, monkeypatch):
    """Test that SEMANTIGUARD_DB_PATH environment variable is respected."""
    custom_path = tmp_path / "custom_location" / "my.db"
    monkeypatch.setenv('SEMANTIGUARD_DB_PATH', str(custom_path))

    # get_db_path should return the custom path
    assert get_db_path() == str(custom_path)

    # init_db should create DB at custom path
    init_db()

    assert custom_path.exists()


def test_db_path_default(monkeypatch):
    """Test that default DB path is used when env var is not set."""
    monkeypatch.delenv('SEMANTIGUARD_DB_PATH', raising=False)

    db_path = get_db_path()

    assert db_path == './semantiguard.db'


def test_cli_lookup_help():
    """Test lookup command help output."""
    runner = CliRunner()
    result = runner.invoke(cli, ['lookup', '--help'])

    assert result.exit_code == 0
    assert 'Lookup CVE advisories' in result.output
    assert '--package' in result.output
    assert '--version' in result.output


def test_cli_init_db_help():
    """Test init-db command help output."""
    runner = CliRunner()
    result = runner.invoke(cli, ['init-db', '--help'])

    assert result.exit_code == 0
    assert 'Initialize the SQLite database' in result.output
