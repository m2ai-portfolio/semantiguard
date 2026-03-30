# SemantiGuard

**Local-First Supply Chain Vulnerability Scanner**

SemantiGuard is a command-line tool that scans AI/LLM dependency manifests for known supply-chain vulnerabilities using a completely offline, semantic analysis approach.

## Features

- **Semantic Parsing**: Parse dependency manifests (requirements.txt, pyproject.toml) to extract package names and versions
- **Local DB Lookup**: Query embedded SQLite database for known CVE entries matching packages
- **CLI Report**: Format scan results as human-readable table or JSON with appropriate exit codes

## Tech Stack

- Python 3.11+
- click (CLI framework)
- pytest (testing)
- SQLite (embedded CVE database)
- pydantic (data models)

## Quick Start

```bash
# Setup
chmod +x init.sh
./init.sh

# Parse a manifest
python -m semantiguard parse requirements.txt

# Initialize CVE database
python -m semantiguard init-db

# Scan for vulnerabilities
python -m semantiguard scan --format table requirements.txt
python -m semantiguard scan --format json requirements.txt
```

## Architecture

```
[User] -> [CLI] -> [Parser] -> [Local DB] -> [Reporter]
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| SEMANTIGUARD_DB_PATH | ./semantiguard.db | Path to local SQLite store |
| SEMANTIGUARD_LOG_LEVEL | INFO | Logging level |
