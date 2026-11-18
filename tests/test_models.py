"""Unit tests for models.py."""

from models import AuditReport, Finding, Severity


def test_audit_report_summary_and_sorting() -> None:
    report = AuditReport(timestamp="2026-01-01 00:00:00 UTC", hostname="node-01")

    assert report.summary() == {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    report.add_finding(
        Finding(
            category="Network",
            target="127.0.0.1:22",
            title="SSH",
            description="SSH open",
            severity=Severity.INFO,
            remediation="Use keys",
        )
    )
    report.add_finding(
        Finding(
            category="Docker",
            target="app",
            title="Privileged",
            description="Privileged container",
            severity=Severity.CRITICAL,
            remediation="Remove --privileged",
        )
    )
    report.add_finding(
        Finding(
            category="Proxmox",
            target="lxc/100",
            title="Privileged LXC",
            description="unprivileged=0",
            severity=Severity.HIGH,
            remediation="Use unprivileged=1",
        )
    )
    report.add_finding(
        Finding(
            category="Network",
            target="127.0.0.1:80",
            title="HTTP",
            description="Plain HTTP",
            severity=Severity.MEDIUM,
            remediation="Use HTTPS",
        )
    )
    report.add_finding(
        Finding(
            category="Docker",
            target="app",
            title="Root user",
            description="Runs as root",
            severity=Severity.LOW,
            remediation="Set USER",
        )
    )

    assert report.summary() == {
        "CRITICAL": 1,
        "HIGH": 1,
        "MEDIUM": 1,
        "LOW": 1,
        "INFO": 1,
    }

    ordered_severities = [f.severity for f in report.sorted_findings()]
    assert ordered_severities == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
