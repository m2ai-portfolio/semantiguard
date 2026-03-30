"""Command-line interface for SemantiGuard."""

import json
import sys
import click

from semantiguard.parser import parse_manifest
from semantiguard.db import init_db, seed_sample_data, lookup_advisories


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


if __name__ == "__main__":
    cli()
