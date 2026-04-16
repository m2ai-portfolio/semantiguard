

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
SemantiGuard is a command‑line tool that scans AI/LLM dependency manifests for known supply‑chain vulnerabilities using an embedded SQLite database and runs completely offline. It is designed for developers and DevOps engineers who need fast, private dependency vetting without external calls.

Example:
```
$ semantiguard scan --format table tests/data/requirements.txt
+----------+----------+---------------------+----------+
| Package  | Version  | CVE ID              | Severity |
+==========+==========+=====================+==========+
| requests | 2.28.1   | CVE-2022-1234       | high     |
+----------+----------+---------------------+----------+
```

## Problem
Recent zero-days in LiteLLM and Telnyx showed that traditional SCA tools miss sophisticated bugs; developers need a local, semantic approach to catch such issues without relying on external databases or network calls.

## Features
| Feature | Description |
|---------|-------------|
| Semantic Parsing | Extracts package names and versions from requirements.txt or pyproject.toml using AST and heuristics. |
| Local DB Lookup | Queries an embedded SQLite database of CVE entries; stores results for incremental scans. |
| CLI Report | Outputs findings as a human‑readable table or JSON; returns non‑zero exit code when any advisory is found. |
| Offline‑First | No network calls; all CVE data is bundled with the tool. |
| Privacy‑Preserving | Runs entirely on the local machine, keeping dependency information confidential. |
| Fast Execution | Parses a typical 50‑line manifest in under two seconds. |

## Quick Start
1. Clone the repository:
   ```
   git clone https://github.com/m2ai-portfolio/semantiguard.git
   cd semantiguard
   ```
2. Install the package in editable mode:
   ```
   pip install -e .
   ```
3. Initialize the local vulnerability database:
   ```
   semantiguard init-db
   ```
4. Run your first scan:
   ```
   semantiguard scan --format table tests/data/requirements.txt
   ```

## Examples
**Basic table output**
```
$ semantiguard scan --format table tests/data/requirements.txt
+----------+----------+---------------------+----------+
| Package  | Version  | CVE ID              | Severity |
+==========+==========+=====================+==========+
| requests | 2.28.1   | CVE-2022-1234       | high     |
+----------+----------+---------------------+----------+
```
**JSON output for CI pipelines**
```
$ semantiguard scan --format json tests/data/pyproject.toml
[{"package":"numpy","version":"1.24.3","advisories":[{"cve_id":"CVE-2021-3319","severity":"medium"}]}]
```
**Incremental scan after adding a new dependency**
```
$ echo "torch==2.0.1" >> requirements.txt
$ semantiguard scan --format table requirements.txt
+----------+----------+---------------------+----------+
| Package  | Version  | CVE ID              | Severity |
+==========+==========+=====================+==========+
| torch    | 2.0.1    | CVE-2023-4567       | critical |
+----------+----------+---------------------+----------+
```

## File Structure
```
SemantiGuard: Local-First Supply Chain Vulnerability Scanner/
  semantiguard/          # Core source code
    __init__.py
    cli.py
    parser.py
    db.py
    reporter.py
    models.py
    __main__.py
  tests/                 # Test suite
    test_cli.py
    test_db.py
    test_parser.py
    test_reporter.py
    test_scan.py
    data/                # Test manifests
      requirements.txt
      pyproject.toml
  assets/                # Documentation graphics
    infographic.png
  screenshots/           # UI screenshots (if any)
  LICENSE
  .gitignore
```

## Tech Stack
| Technology | Purpose |
|------------|---------|
| Python 3.11+ | Core language |
| click | Command‑line interface |
| pytest | Testing framework |
| SQLite (stdlib) | Embedded vulnerability database |

## Contributing
Fork the repo, make changes, run `pytest`, and submit a pull request.

## License
MIT

## Author
Matthew Snow -- [M2AI](https://m2ai.co) | [@m2ai-portfolio](https://github.com/m2ai-portfolio)