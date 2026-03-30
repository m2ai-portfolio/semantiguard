"""Reporter module for formatting scan results."""

import json
from typing import List

from semantiguard.models import ScanResult


def format_table(scan_results: List[ScanResult]) -> str:
    """Format scan results as a human-readable table.

    Args:
        scan_results: List of ScanResult objects

    Returns:
        Formatted table string
    """
    if not has_findings(scan_results):
        return "No vulnerabilities found."

    # Calculate column widths
    max_package = max(len(result.package) for result in scan_results)
    max_version = max(len(result.version) for result in scan_results)

    # Calculate max widths from advisories
    max_cve = 0
    max_severity = 0
    max_description = 0

    for result in scan_results:
        for advisory in result.advisories:
            max_cve = max(max_cve, len(advisory.cve_id))
            max_severity = max(max_severity, len(advisory.severity))
            if advisory.description:
                max_description = max(max_description, len(advisory.description))

    # Set minimum column widths based on headers
    max_package = max(max_package, len("Package"))
    max_version = max(max_version, len("Version"))
    max_cve = max(max_cve, len("CVE ID"))
    max_severity = max(max_severity, len("Severity"))
    max_description = max(max_description, len("Description"))

    # Cap description width to 50 characters for readability
    max_description = min(max_description, 50)

    # Build table
    lines = []

    # Header
    separator = f"+-{'-' * max_package}-+-{'-' * max_version}-+-{'-' * max_cve}-+-{'-' * max_severity}-+-{'-' * max_description}-+"
    lines.append(separator)

    header = f"| {'Package':<{max_package}} | {'Version':<{max_version}} | {'CVE ID':<{max_cve}} | {'Severity':<{max_severity}} | {'Description':<{max_description}} |"
    lines.append(header)
    lines.append(separator)

    # Data rows
    total_findings = 0
    affected_packages = set()

    for result in scan_results:
        for advisory in result.advisories:
            total_findings += 1
            affected_packages.add(result.package)

            description = advisory.description if advisory.description else ""
            if len(description) > max_description:
                description = description[:max_description - 3] + "..."

            row = f"| {result.package:<{max_package}} | {result.version:<{max_version}} | {advisory.cve_id:<{max_cve}} | {advisory.severity:<{max_severity}} | {description:<{max_description}} |"
            lines.append(row)

    # Footer
    lines.append(separator)
    lines.append("")
    lines.append(f"Found {total_findings} vulnerabilities in {len(affected_packages)} packages.")

    return "\n".join(lines)


def format_json(scan_results: List[ScanResult]) -> str:
    """Format scan results as valid JSON.

    Args:
        scan_results: List of ScanResult objects

    Returns:
        JSON string
    """
    # Convert ScanResult objects to dictionaries
    results_dict = [result.model_dump() for result in scan_results]
    return json.dumps(results_dict, indent=2)


def has_findings(scan_results: List[ScanResult]) -> bool:
    """Check if any scan results contain advisories.

    Args:
        scan_results: List of ScanResult objects

    Returns:
        True if any results have advisories, False otherwise
    """
    return any(len(result.advisories) > 0 for result in scan_results)
