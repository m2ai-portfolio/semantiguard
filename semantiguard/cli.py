"""Command-line interface for SemantiGuard."""

import json
import sys
import click

from semantiguard.parser import parse_manifest


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


if __name__ == "__main__":
    cli()
