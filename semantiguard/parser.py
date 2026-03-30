"""Parser module for dependency manifests."""

import logging
import re
import sys
from pathlib import Path
from typing import List

# Use tomllib (Python 3.11+) or fallback to tomli
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        import tomllib

from semantiguard.models import Dependency

logger = logging.getLogger(__name__)


def parse_requirements_txt(file_path: Path) -> List[Dependency]:
    """Parse a requirements.txt file and extract dependencies.

    Args:
        file_path: Path to the requirements.txt file

    Returns:
        List of Dependency objects

    Raises:
        IOError: If the file cannot be read
        PermissionError: If the file cannot be accessed
    """
    dependencies = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Match package==version pattern
                match = re.match(r'^([a-zA-Z0-9_-]+)\s*==\s*([0-9.]+.*?)(?:\s|$)', line)
                if match:
                    name, version = match.groups()
                    dependencies.append(Dependency(name=name, version=version))
                else:
                    # Try to match package>=version or other operators
                    match = re.match(r'^([a-zA-Z0-9_-]+)\s*[><=!]+\s*([0-9.]+.*?)(?:\s|$)', line)
                    if match:
                        name, version = match.groups()
                        dependencies.append(Dependency(name=name, version=version))
                    else:
                        # Log warning for unparseable lines
                        logger.warning(f"Could not parse dependency line: {line}")

    except (IOError, PermissionError) as e:
        raise IOError(f"Failed to read file {file_path}: {e}")

    return dependencies


def parse_pyproject_toml(file_path: Path) -> List[Dependency]:
    """Parse a pyproject.toml file and extract dependencies.

    Args:
        file_path: Path to the pyproject.toml file

    Returns:
        List of Dependency objects

    Raises:
        IOError: If the file cannot be read
        PermissionError: If the file cannot be accessed
        ValueError: If the TOML file is invalid
    """
    dependencies = []

    try:
        with open(file_path, 'rb') as f:
            data = tomllib.load(f)
    except (IOError, PermissionError) as e:
        raise IOError(f"Failed to read file {file_path}: {e}")
    except Exception as e:
        raise ValueError(f"Failed to parse TOML file {file_path}: {e}")

    # Try [project] dependencies first (PEP 621)
    project_deps = data.get('project', {}).get('dependencies', [])
    for dep in project_deps:
        # Parse "package>=version" or "package==version" format
        match = re.match(r'^([a-zA-Z0-9_-]+)\s*[><=!]+\s*([0-9.]+.*?)(?:\s|,|$)', dep)
        if match:
            name, version = match.groups()
            dependencies.append(Dependency(name=name, version=version))
        else:
            logger.warning(f"Could not parse dependency line: {dep}")

    # Try [tool.poetry.dependencies] (Poetry format)
    poetry_deps = data.get('tool', {}).get('poetry', {}).get('dependencies', {})
    for name, version_spec in poetry_deps.items():
        if name == 'python':
            continue

        # Handle different version specification formats
        if isinstance(version_spec, str):
            # Extract version from string like "^2.0.0" or ">=2.0.0"
            match = re.match(r'[^0-9]*([0-9.]+.*?)(?:\s|,|$)', version_spec)
            if match:
                version = match.group(1)
                dependencies.append(Dependency(name=name, version=version))
            else:
                logger.warning(f"Could not parse version for dependency: {name} = {version_spec}")
        elif isinstance(version_spec, dict):
            # Handle dict format like {version = "^2.0.0"}
            version = version_spec.get('version', '')
            match = re.match(r'[^0-9]*([0-9.]+.*?)(?:\s|,|$)', version)
            if match:
                version = match.group(1)
                dependencies.append(Dependency(name=name, version=version))
            else:
                logger.warning(f"Could not parse version for dependency: {name} = {version_spec}")

    return dependencies


def parse_manifest(file_path: str) -> List[Dependency]:
    """Parse a dependency manifest file.

    Args:
        file_path: Path to the manifest file

    Returns:
        List of Dependency objects

    Raises:
        FileNotFoundError: If the file does not exist
        ValueError: If the file type is not supported
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if path.name == 'requirements.txt' or path.suffix == '.txt':
        return parse_requirements_txt(path)
    elif path.name == 'pyproject.toml' or path.suffix == '.toml':
        return parse_pyproject_toml(path)
    else:
        raise ValueError(f"Unsupported file type: {path.name}")
