"""Standalone HTML and optional PDF report generator."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from rich.console import Console

from models import AuditReport

_TEMPLATE_DIR = Path(__file__).resolve().parent
_TEMPLATE_NAME = "template.html"


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

    rendered_html = template.render(
        report=report,
        summary=report.summary(),
        findings=report.sorted_findings(),
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
