"""Data models for SemantiGuard."""

from typing import List, Optional
from pydantic import BaseModel


class Dependency(BaseModel):
    """Represents a dependency with name and version."""

    name: str
    version: str


class Advisory(BaseModel):
    """Represents a security advisory for a package."""

    cve_id: str
    severity: str
    description: Optional[str] = None


class ScanResult(BaseModel):
    """Represents the scan result for a package."""

    package: str
    version: str
    advisories: List[Advisory]
