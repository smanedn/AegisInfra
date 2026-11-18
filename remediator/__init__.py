"""Safe, interactive auto-remediation engine for AegisInfra."""

from remediator.fixer import count_fixable_findings, get_fixable_findings, run_remediation

__all__ = ["count_fixable_findings", "get_fixable_findings", "run_remediation"]
