"""Command-line interface for SemantiGuard."""

import json
import sys
import click
from pathlib import Path

from semantiguard.parser import parse_manifest
from semantiguard.db import init_db, seed_sample_data, lookup_advisories
from semantiguard.models import ScanResult, Advisory
from semantiguard.reporter import format_table, format_json, has_findings


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """SemantiGuard - Local-first supply chain vulnerability scanner."""
    pass


@cli.command()
@click.argument('file_path', type=click.Path(exists=False, resolve_path=True))
def parse(file_path: str):
    """Parse a dependency manifest file and output JSON.

    Supported formats:
    - requirements.txt
    - pyproject.toml

    Example:
        semantiguard parse requirements.txt
    """
    try:
        dependencies = parse_manifest(file_path)

        # Convert to dict format for JSON output
        output = [{"name": dep.name, "version": dep.version} for dep in dependencies]

        # Print JSON output
        click.echo(json.dumps(output, indent=2))

    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)
    except (ValueError, IOError, PermissionError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command()
def init_db_command():
    """Initialize the SQLite database and seed with sample CVE data.

    Creates the database file at SEMANTIGUARD_DB_PATH (default: ./semantiguard.db)
    with the advisories table schema and populates it with sample vulnerability data.

    Example:
        semantiguard init-db
    """
    try:
        init_db()
        seed_sample_data()
        click.echo("DB initialized")
    except Exception as e:
        click.echo(f"Error initializing database: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--package', required=True, help='Package name to lookup')
@click.option('--version', required=True, help='Package version to lookup')
def lookup(package: str, version: str):
    """Lookup CVE advisories for a specific package and version.

    Queries the local SQLite database for known vulnerabilities matching
    the provided package name and version.

    Example:
        semantiguard lookup --package requests --version 2.28.1
    """
    try:
        advisories = lookup_advisories(package, version)
        click.echo(json.dumps(advisories, indent=2))
    except Exception as e:
        click.echo(f"Error looking up advisories: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('file_path', type=click.Path(exists=False, resolve_path=True))
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']), default='table', help='Output format')
def scan(file_path: str, output_format: str):
    """Scan a dependency manifest for known vulnerabilities.

    Parses the manifest file, queries the local database for known CVEs,
    and reports findings in table or JSON format.

    Supported manifest formats:
    - requirements.txt
    - pyproject.toml

    Exit codes:
    - 0: No vulnerabilities found
    - 1: Vulnerabilities found
    - 2: File not found or other error

    Example:
        semantiguard scan requirements.txt
        semantiguard scan --format json pyproject.toml
    """
    try:
        # Check if database exists, initialize if needed
        from semantiguard.db import get_db_path
        db_path = Path(get_db_path())
        if not db_path.exists():
            click.echo("Database not initialized. Run 'semantiguard init-db' first.", err=True)
            sys.exit(2)

        # Parse the manifest file
        dependencies = parse_manifest(file_path)

        # Lookup advisories for each dependency
        scan_results = []
        for dep in dependencies:
            advisories_data = lookup_advisories(dep.name, dep.version)
            advisories = [
                Advisory(
                    cve_id=adv['cve_id'],
                    severity=adv['severity'],
                    description=adv.get('description')
                )
                for adv in advisories_data
            ]
            scan_results.append(ScanResult(
                package=dep.name,
                version=dep.version,
                advisories=advisories
            ))

        # Format and output results
        if output_format == 'json':
            output = format_json(scan_results)
        else:
            output = format_table(scan_results)

        click.echo(output)

        # Exit with appropriate code
        if has_findings(scan_results):
            sys.exit(1)
        else:
            sys.exit(0)

    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)
    except (ValueError, IOError, PermissionError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(2)


if __name__ == "__main__":
    cli()
