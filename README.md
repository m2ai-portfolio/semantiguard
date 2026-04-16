

<p align="center">
  <img src="assets/infographic.png" alt="SemantiGuard: Local-First Supply Chain Vulnerability Scanner" width="800">
</p>

<h3 align="center">A CLI tool that uses semantic analysis to detect zero-day supply chain threats in AI/LLM dependencies, running entirely offline for privacy and speed.</h3>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#examples">Examples</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

## What is this?
SemantiGuard scans local AI/LLM dependency manifests for known vulnerabilities using an embedded SQLite database, providing fast, privacy‑first security checks without any network calls. It is aimed at developers and DevOps engineers who need to vet packages offline.

Example usage:
```
$ semantiguard scan --format table tests/data/requirements.txt
+----------+----------+------------------+----------+
| Package  | Version  | CVE ID           | Severity |
+----------+----------+------------------+----------+
| requests | 2.28.1   | CVE-2022-1234    | high     |
| numpy    | 1.24.3   | -                | -        |
+----------+----------+------------------+----------+
```

## Problem
Recent zero-days in LiteLLM and Telnyx showed that traditional SCA tools miss sophisticated bugs; developers need a local, semantic approach to catch such issues without relying on external databases or network calls.

## Features
| Feature | Description |
|---|---|
| Semantic Parsing | Extracts package names and versions from requirements.txt or pyproject.toml using AST and heuristics. |
| Local DB Lookup | Queries an embedded SQLite database for CVE entries matching scanned packages. |
| CLI Reporting | Outputs results as a readable table or JSON; returns non‑zero exit code when advisories are found. |
| Offline Operation | No external API calls; all CVE data is bundled with the tool for privacy and speed. |
| Incremental Scanning | Stores scan results locally to enable fast repeat scans without re‑parsing manifests. |
| Flexible Output | Supports `--format table|json` to integrate with scripts or CI pipelines. |
| Graceful Error Handling | Exits with code 2 and a clear message if a manifest file is missing or unreadable. |
| Incremental DB Updates | Upserts new findings into the SQLite store for future reference. |

## Quick Start
1. Clone the repository:
   ```bash
   git clone https://github.com/m2ai-portfolio/SemantiGuard.git
   cd SemantiGuard
   ```
2. Install the tool in editable mode:
   ```bash
   pip install -e .
   ```
3. Initialize the local CVE database:
   ```bash
   semantiguard init-db
   ```
4. Scan a sample manifest:
   ```bash
   semantiguard scan --format table tests/data/requirements.txt
   ```

## Examples
**Parse a manifest to JSON**
```bash
$ semantiguard parse tests/data/requirements.txt
[{"name":"requests","version":"2.28.1"},{"name":"numpy","version":"1.24.3"}]
```

**Lookup a specific package version**
```bash
$ semantiguard lookup --package requests --version 2.28.1
[{"cve_id":"CVE-2022-1234","severity":"high"}]
```

**Scan with JSON output for CI**
```bash
$ semantiguard scan --format json tests/data/pyproject.toml
[{"package":"requests","version":"2.28.1","advisories":[{"cve_id":"CVE-2022-1234","severity":"high","description":"Example description"}]}]
```

## File Structure
```
SemantiGuard: Local-First Supply Chain Vulnerability Scanner/
  semantiguard/        # Core source code
    cli.py             # Command‑line interface entry point
    parser.py          # Manifest parsing logic (requirements.txt, pyproject.toml)
    db.py              # SQLite database handling and schema
    reporter.py        # Table and JSON output formatting
    models.py          # Pydantic models for Advisory and ScanResult
  tests/               # Test suite
    test_cli.py
    test_parser.py
    test_db.py
    test_reporter.py
    test_scan.py
  tests/data/          # Sample manifest files used in tests and examples
    requirements.txt
    pyproject.toml
  assets/              # Infographic used in the banner
    infographic.png
  LICENSE
  README.md
```

## Tech Stack
| Technology | Purpose |
|---|---|
| Python 3.11+ | Core language runtime |
| click | Building the command‑line interface |
| pytest | Running unit and integration tests |
| sqlite3 (stdlib) | Embedded CVE database storage |
| pydantic | Data validation and serialization for models |

## Contributing
Fork the repo, make your changes, run `pytest` to verify, then submit a pull request.

## License
MIT

## Author
Matthew Snow -- [M2AI](https://m2ai.co) | [@m2ai-portfolio](https://github.com/m2ai-portfolio)