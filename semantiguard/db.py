"""Database module for SemantiGuard SQLite CVE database."""

import os
import sqlite3
from typing import List, Optional
from pathlib import Path


# Sample CVE data for testing/seeding
SAMPLE_ADVISORIES = [
    ("CVE-2023-32681", "requests", "2.28.1", "high", "Unintended leak of Proxy-Authorization header"),
    ("CVE-2023-45803", "requests", "2.28.1", "medium", "Cookie handling vulnerability"),
    ("CVE-2023-41105", "numpy", "1.24.3", "medium", "Path traversal in numpy.load"),
    ("CVE-2023-25577", "flask", "2.3.0", "high", "Denial of service via multipart parsing"),
    ("CVE-2024-34064", "pydantic", "2.0.0", "low", "Model validation bypass"),
]


def get_db_path() -> str:
    """Get the database path from environment or default.

    Returns:
        str: Path to the SQLite database file
    """
    return os.environ.get('SEMANTIGUARD_DB_PATH', './semantiguard.db')


def init_db(db_path: Optional[str] = None) -> None:
    """Initialize the SQLite database with advisories table schema.

    Args:
        db_path: Optional path to database file. If None, uses get_db_path()
    """
    if db_path is None:
        db_path = get_db_path()

    # Create parent directory if it doesn't exist
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Create advisories table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS advisories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL UNIQUE,
                package_name TEXT NOT NULL,
                affected_version TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'unknown',
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes for performance
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_advisories_package
            ON advisories(package_name)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_advisories_cve
            ON advisories(cve_id)
        """)

        conn.commit()
    finally:
        conn.close()


def seed_sample_data(db_path: Optional[str] = None) -> None:
    """Insert sample CVE data for testing.

    Args:
        db_path: Optional path to database file. If None, uses get_db_path()
    """
    if db_path is None:
        db_path = get_db_path()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        for cve_id, package_name, version, severity, description in SAMPLE_ADVISORIES:
            cursor.execute("""
                INSERT OR REPLACE INTO advisories
                (cve_id, package_name, affected_version, severity, description)
                VALUES (?, ?, ?, ?, ?)
            """, (cve_id, package_name, version, severity, description))

        conn.commit()
    finally:
        conn.close()


def lookup_advisories(package_name: str, version: str, db_path: Optional[str] = None) -> List[dict]:
    """Query database for advisories matching package name and version.

    Args:
        package_name: Name of the package to lookup
        version: Version string of the package
        db_path: Optional path to database file. If None, uses get_db_path()

    Returns:
        List of advisory dictionaries with keys: cve_id, package_name, affected_version,
        severity, description
    """
    if db_path is None:
        db_path = get_db_path()

    # Check if database file exists
    if not Path(db_path).exists():
        return []

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT cve_id, package_name, affected_version, severity, description
            FROM advisories
            WHERE package_name = ? AND affected_version = ?
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                cve_id ASC
        """, (package_name, version))

        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def upsert_advisory(
    cve_id: str,
    package_name: str,
    version: str,
    severity: str,
    description: Optional[str] = None,
    db_path: Optional[str] = None
) -> None:
    """Insert or replace an advisory in the database.

    Args:
        cve_id: CVE identifier
        package_name: Name of the affected package
        version: Affected version string
        severity: Severity level (e.g., 'low', 'medium', 'high', 'critical')
        description: Optional description of the vulnerability
        db_path: Optional path to database file. If None, uses get_db_path()
    """
    if db_path is None:
        db_path = get_db_path()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT OR REPLACE INTO advisories
            (cve_id, package_name, affected_version, severity, description)
            VALUES (?, ?, ?, ?, ?)
        """, (cve_id, package_name, version, severity, description))

        conn.commit()
    finally:
        conn.close()
