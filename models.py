"""Core data models for AegisInfra security audit findings and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Security finding severity levels ordered from highest to lowest risk."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass(slots=True)
class Finding:
    """Represents a single security finding discovered during an audit."""

    category: str
    target: str
    title: str
    description: str
    severity: Severity
    remediation: str


@dataclass(slots=True)
class AuditReport:
    """Aggregates all security findings and metadata for an audit run."""

    timestamp: str
    hostname: str
    findings: list[Finding] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        """Append a security finding to the report."""
        self.findings.append(finding)

    def summary(self) -> dict[str, int]:
        """Return a mapping of severity level names to finding counts."""
        counts: dict[str, int] = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        """Return findings sorted from most severe (CRITICAL) to least (INFO)."""
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.category, f.target),
        )
