

# SemantiGuard: Local-First Supply Chain Vulnerability Scanner  
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)  
![License: MIT](https://img.shields.io/badge/license-MIT-green)  

## Overview  
SemantiGuard is a command‑line tool that scans AI/LLM dependency manifests (e.g., `requirements.txt`, `pyproject.toml`) for known supply‑chain vulnerabilities using a completely offline, semantic analysis approach. It extracts package names and versions locally, checks them against an embedded SQLite database of CVE entries, and reports findings in a human‑readable table or JSON. Designed for developers and DevOps engineers who need fast, privacy‑preserving vulnerability vetting without any network calls.

## Problem Statement  
Existing software composition analysis (SCA) tools depend on online APIs and often miss zero‑day bugs in niche AI/LLM packages, leaving developers exposed to sophisticated supply‑chain attacks. SemantiGuard solves this by providing a fully local scanner that never contacts external services, ensuring privacy and immediate detection of known CVEs bundled with the tool.

## Features  
- **Semantic Parsing** – Reads `requirements.txt` and `pyproject.toml`, extracts package names/versions using AST and heuristics.  
- **Local DB Lookup** – Queries an embedded SQLite database for matching CVE entries; initializes and upserts results on first run.  
- **CLI Reporting** – Outputs results as a table or JSON via `--format` flag; returns exit code 0 when clean, 1 when advisories are found.  
- **Offline‑First** – No external API calls; all CVE data ships with the SQLite DB.  
- **Incremental Scans** – Stores scan results locally for fast re‑scans.  
- **Fast Performance** – Parses a typical 50‑line manifest in under 2 seconds.  
- **Tested** – Includes unit tests for CLI, parser, DB, reporter, and end‑to‑end scanning.

## Tech Stack  
- **Language**: Python 3.11+  
- **CLI Framework**: Click  
- **Testing**: Pytest  
- **Data Storage**: SQLite (standard library)  
- **Data Validation**: Pydantic (used in internal models)

## Quick Start / Installation  

1. **Clone the repository**  
   ```bash
   git clone https://github.com/your-org/semantiguard.git
   cd semantiguard
   ```

2. **Create a virtual environment (optional but recommended)**  
   ```bash
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   ```

3. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the local CVE database**  
   ```bash
   semantiguard init-db
   ```
   You should see `DB initialized`.

5. **Verify installation**  
   ```bash
   semantiguard --help
   ```

## Usage  

### Scan a manifest  
```bash
# Table output (default)
semantiguard scan path/to/requirements.txt

# JSON output
semantiguard scan --format json path/to/pyproject.toml
```
The command returns exit code 0 if no advisories are found, 1 otherwise.

### Lookup a specific package  
```bash
semantiguard lookup --package requests --version 2.28.1
```

### Parse a manifest (extract packages only)  
```bash
semantiguard parse path/to/requirements.txt
```

### Re‑initialize the database (if needed)  
```bash
semantiguard init-db
```

### Set logging level (via environment variable)  
```bash
export SEMANTIGUARD_LOG_LEVEL=DEBUG
semantiguard scan path/to/requirements.txt
```

## Architecture  

```
[User] --> [CLI] --> [Parser] --> [Local DB (SQLite)] --> [Reporter]
```

- **CLI (`cli.py`)**: Handles command‑line arguments, flags, and dispatching to sub‑commands (`scan`, `parse`, `lookup`, `init-db`).  
- **Parser (`parser.py`)**: Reads manifest files, uses AST and regex heuristics to yield `{name, version}` pairs.  
- **DB (`db.py`)**: Manages SQLite connection, schema creation (`CREATE TABLE IF NOT EXISTS advisories …`), and query/upsert operations.  
- **Reporter (`reporter.py`)**: Formats the list of advisories as a markdown‑style table or JSON and writes to stdout.  
- **Models (`models.py`)**: Pydantic models `Advisory` and `ScanResult` for type safety.  

The flow ensures zero network interaction; all data resides in the bundled `semantiguard.db`.

## License  

MIT License  

Copyright (c) 2025 SemantiGuard Contributors  

Permission is hereby granted, free of charge, to any person obtaining a copy  
of this software and associated documentation files (the "Software"), to deal  
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
copies of the Software, and to permit persons to whom the Software is  
furnished to do so, subject to the following conditions:  

The above copyright notice and this permission notice shall be included in all  
copies or substantial portions of the Software.  

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER  
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  
SOFTWARE.