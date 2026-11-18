"""Standalone HTML and optional PDF report generator."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from rich.console import Console

from models import AuditReport, Finding, RemediationLog

_TEMPLATE_DIR = Path(__file__).resolve().parent
_TEMPLATE_NAME = "template.html"


def _calculate_security_score(
    summary: dict[str, int],
) -> tuple[int, str, str]:
    """Compute a 0-100 posture score, rating label, and accent hex color."""
    penalty = (
        summary.get("CRITICAL", 0) * 25
        + summary.get("HIGH", 0) * 15
        + summary.get("MEDIUM", 0) * 7
        + summary.get("LOW", 0) * 3
    )
    score = max(0, 100 - penalty)
    if score >= 90:
        return score, "Excellent", "#22c55e"
    if score >= 75:
        return score, "Good", "#38bdf8"
    if score >= 50:
        return score, "Fair", "#eab308"
    return score, "At Risk", "#ef4444"


def _cli_snippet_for_finding(finding: Finding) -> str:
    """Return a ready-to-copy CLI snippet for a fixable finding."""
    mapping = {
        "docker.privileged": "python main.py scan --fix  # generates hardened docker-compose.override.yml",
        "docker.sensitive_mount": "python main.py scan --fix  # adds no-new-privileges override",
        "docker.wildcard_port": "python main.py scan --fix  # rebinds 0.0.0.0 ports to 127.0.0.1",
        "docker.prune_images": "docker image prune -f",
        "proxmox.cluster_firewall": "pvesh set /cluster/firewall/options -enable 1",
        "proxmox.node_firewall": f"pvesh set /nodes/{finding.target.removeprefix('node/')}/firewall/options -enable 1",
        "proxmox.guest_firewall": "python main.py scan --fix  # enables firewall=1 via Proxmox API",
    }
    return mapping.get(finding.fix_id or "", "python main.py scan --fix")


def _match_applied_remediation(
    finding: Finding,
    applied_logs: list[RemediationLog],
) -> RemediationLog | None:
    """Find an APPLIED remediation log matching the given finding."""
    for log in applied_logs:
        if log.target == finding.target:
            return log
        if finding.fix_id in {"docker.privileged", "docker.sensitive_mount", "docker.wildcard_port"} and log.target == "Docker Compose":
            return log
        if finding.fix_id == "docker.prune_images" and log.target == "Docker Images":
            return log
    return None


def _build_finding_views(
    findings: list[Finding],
    remediations: list[RemediationLog],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Attach fix status metadata to each finding and return status counts."""
    applied_logs = [r for r in remediations if r.status == "APPLIED"]
    views: list[dict[str, Any]] = []
    counts = {"FIXED": 0, "FIX AVAILABLE": 0, "MANUAL REVIEW": 0}

    for finding in findings:
        matched = _match_applied_remediation(finding, applied_logs)
        if matched is not None:
            fix_status = "FIXED"
            applied_action = matched.action
            fix_command = ""
        elif finding.fix_id is not None:
            fix_status = "FIX AVAILABLE"
            applied_action = ""
            fix_command = _cli_snippet_for_finding(finding)
        else:
            fix_status = "MANUAL REVIEW"
            applied_action = ""
            fix_command = ""

        counts[fix_status] += 1
        views.append(
            {
                "finding": finding,
                "fix_status": fix_status,
                "applied_action": applied_action,
                "fix_command": fix_command,
            }
        )

    return views, counts


def generate_report(
    report: AuditReport,
    output_dir: str | Path,
    generate_pdf: bool = False,
    console: Console | None = None,
) -> tuple[Path, Path | None]:
    """Render an AuditReport to a standalone HTML file and optionally a PDF file.

    Args:
        report: Populated AuditReport instance.
        output_dir: Directory where report files should be written.
        generate_pdf: Whether to also export a PDF using WeasyPrint.
        console: Optional Rich console for warnings.

    Returns:
        Tuple of ``(html_path, pdf_path)``. ``pdf_path`` is ``None`` if PDF
        generation was skipped or failed due to missing system dependencies.
    """
    out = console or Console()
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template(_TEMPLATE_NAME)

    summary = report.summary()
    sorted_findings = report.sorted_findings()
    finding_views, fix_counts = _build_finding_views(sorted_findings, report.remediations)

    before_score, _, _ = _calculate_security_score(summary)
    remaining_summary = {sev: 0 for sev in summary}
    for view in finding_views:
        if view["fix_status"] != "FIXED":
            remaining_summary[view["finding"].severity.value] += 1

    has_applied_fixes = any(r.status == "APPLIED" for r in report.remediations)
    security_score, score_label, score_color = _calculate_security_score(
        remaining_summary if has_applied_fixes else summary
    )

    rendered_html = template.render(
        report=report,
        summary=summary,
        findings=sorted_findings,
        finding_views=finding_views,
        fix_counts=fix_counts,
        has_applied_fixes=has_applied_fixes,
        before_score=before_score,
        security_score=security_score,
        score_label=score_label,
        score_color=score_color,
    )

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = target_dir / f"aegis_report_{stamp}.html"
    html_path.write_text(rendered_html, encoding="utf-8")

    pdf_path: Path | None = None
    if generate_pdf:
        try:
            from weasyprint import HTML  # type: ignore[import-untyped]

            candidate_pdf = target_dir / f"aegis_report_{stamp}.pdf"
            HTML(string=rendered_html, base_url=str(_TEMPLATE_DIR)).write_pdf(str(candidate_pdf))
            pdf_path = candidate_pdf
        except (ImportError, OSError) as exc:
            out.print(
                "[yellow]Warning: PDF export skipped because WeasyPrint or its system "
                f"GTK/Pango libraries are unavailable ({exc}). HTML report was saved.[/yellow]"
            )
        except Exception as exc:
            out.print(f"[yellow]Warning: PDF export failed ({exc}). HTML report was saved.[/yellow]")

    return html_path, pdf_path
