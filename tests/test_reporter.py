"""Unit tests for reporter/generator.py and reporter/template.html."""

from pathlib import Path

from rich.console import Console

from models import AuditReport, Finding, Severity
from reporter.generator import generate_report


def test_generate_report_renders_and_escapes_xss(tmp_path: Path) -> None:
    report = AuditReport(timestamp="2026-01-01 00:00:00 UTC", hostname="test-host")
    xss_payload = "<script>alert('xss')</script>"
    report.add_finding(
        Finding(
            category="Network",
            target=f"127.0.0.1:80 ({xss_payload})",
            title="XSS Banner Test",
            description=f"Banner returned {xss_payload}",
            severity=Severity.MEDIUM,
            remediation="Use HTTPS",
        )
    )

    html_path, pdf_path = generate_report(
        report=report,
        output_dir=tmp_path,
        generate_pdf=False,
        console=Console(quiet=True),
    )

    assert pdf_path is None
    assert html_path.exists()
    content = html_path.read_text(encoding="utf-8")

    assert "test-host" in content
    assert xss_payload not in content
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in content
