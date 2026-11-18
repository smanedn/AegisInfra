"""AegisInfra CLI entry point."""

from __future__ import annotations

import os
import shutil
import socket
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from models import AuditReport, Finding, Severity
from remediator import get_fixable_findings, run_remediation
from reporter import generate_report
from scanner import run_docker_audit, run_network_scan, run_proxmox_audit

app = typer.Typer(
    name="aegisinfra",
    help="AegisInfra — Security auditing CLI for self-hosted infrastructure, Docker, and Proxmox VE.",
    add_completion=False,
    pretty_exceptions_show_locals=False,
)
console = Console()

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold orange1",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "dim white",
}

_SEVERITY_BADGES: dict[Severity, str] = {
    Severity.CRITICAL: "[bold white on red] CRITICAL [/bold white on red]",
    Severity.HIGH: "[bold white on dark_orange]   HIGH   [/bold white on dark_orange]",
    Severity.MEDIUM: "[bold black on yellow]  MEDIUM  [/bold black on yellow]",
    Severity.LOW: "[bold white on blue]   LOW    [/bold white on blue]",
    Severity.INFO: "[bold white on bright_black]   INFO   [/bold white on bright_black]",
}


def _check_config_permissions(config_path: Path) -> None:
    """Warn on POSIX systems if the config file has overly permissive permissions."""
    if os.name == "nt":
        return
    try:
        mode = stat.S_IMODE(config_path.stat().st_mode)
    except OSError:
        return
    if mode not in (0o600, 0o640, 0o400, 0o440):
        console.print(
            f"[yellow]Warning: '{config_path}' has overly permissive file permissions "
            f"({oct(mode)}). Run 'chmod 600 {config_path}' to protect API tokens.[/yellow]"
        )


def _load_config(config_path: Path) -> dict[str, Any]:
    """Load and validate YAML configuration."""
    if not config_path.exists():
        console.print(
            f"[red]Error: Configuration file '{config_path}' not found.[/red]\n"
            "Run [bold]python main.py init-config[/bold] to create one from config.example.yaml."
        )
        raise typer.Exit(code=1)

    _check_config_permissions(config_path)

    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        problem = getattr(exc, "problem", None) or "invalid YAML syntax"
        console.print(f"[red]Error: Failed to parse YAML config '{config_path}' ({problem}).[/red]")
        raise typer.Exit(code=1) from None

    if not isinstance(data, dict):
        console.print(f"[red]Error: Configuration '{config_path}' must be a YAML mapping.[/red]")
        raise typer.Exit(code=1)

    return data


def _render_terminal_summary(report: AuditReport) -> None:
    """Display severity counts and findings table in the terminal."""
    counts = report.summary()

    summary_table = Table(title="Severity Summary", show_header=True, header_style="bold")
    for sev in Severity:
        summary_table.add_column(sev.value, justify="center", style=_SEVERITY_STYLES[sev])
    summary_table.add_row(*(str(counts[sev.value]) for sev in Severity))
    console.print()
    console.print(summary_table)

    sorted_findings = report.sorted_findings()
    if not sorted_findings:
        console.print("\n[bold green]No security findings detected across enabled modules.[/bold green]")
        return

    findings_table = Table(
        title=f"Audit Findings ({len(sorted_findings)} total)",
        show_lines=True,
        header_style="bold cyan",
    )
    findings_table.add_column("Severity", width=10, no_wrap=True)
    findings_table.add_column("Category", width=10, no_wrap=True)
    findings_table.add_column("Target", max_width=28)
    findings_table.add_column("Title", max_width=38)
    findings_table.add_column("Remediation", max_width=46)

    for finding in sorted_findings:
        badge = _SEVERITY_BADGES.get(finding.severity, finding.severity.value)
        findings_table.add_row(
            badge,
            finding.category,
            finding.target,
            finding.title,
            finding.remediation,
        )

    console.print()
    console.print(findings_table)


@app.command("init-config")
def init_config() -> None:
    """Copy config.example.yaml to config.yaml if it does not already exist."""
    base_dir = Path(__file__).resolve().parent
    example_path = base_dir / "config.example.yaml"
    target_path = Path("config.yaml")

    if target_path.exists():
        console.print(f"[yellow]'{target_path}' already exists. Skipping copy to avoid overwriting.[/yellow]")
        raise typer.Exit(code=0)

    if not example_path.exists():
        console.print(f"[red]Error: Template '{example_path}' was not found.[/red]")
        raise typer.Exit(code=1)

    shutil.copy2(example_path, target_path)
    console.print(
        f"[bold green]Created '{target_path}' from '{example_path.name}'.[/bold green]\n"
        "Edit [bold]config.yaml[/bold] with your targets and credentials, then run: "
        "[bold cyan]python main.py scan[/bold cyan]"
    )


def _prompt_interactive_remediation(
    report: AuditReport,
    cfg: dict[str, Any],
    config_path: Path,
    output_dir: Path,
    export_pdf: bool,
    html_path: Path,
) -> Path:
    """Display an interactive fix menu after report generation and regenerate report if fixes run."""
    fixable = get_fixable_findings(report)
    if not fixable:
        return html_path

    menu_table = Table(
        title=f"Available Safe Remediations ({len(fixable)})",
        show_lines=True,
        header_style="bold cyan",
    )
    menu_table.add_column("#", width=4, justify="right", style="bold")
    menu_table.add_column("Severity", width=12, no_wrap=True)
    menu_table.add_column("Target", max_width=28)
    menu_table.add_column("Proposed Safe Fix", max_width=52)

    for idx, item in enumerate(fixable, start=1):
        badge = _SEVERITY_BADGES.get(item.severity, item.severity.value)
        menu_table.add_row(
            str(idx),
            badge,
            item.target,
            item.fix_description or item.remediation,
        )

    console.print()
    console.print(menu_table)
    console.print(
        "\n[bold][A][/bold] Fix all safe issues automatically\n"
        "[bold][S][/bold] Select specific issues to fix (e.g. 1,3)\n"
        "[bold][N][/bold] Skip fixes and open report"
    )

    choice = typer.prompt("Choose an option [A/S/N]", default="N").strip().upper()
    if choice not in ("A", "S"):
        return html_path

    selected: list[Finding] = fixable
    if choice == "S":
        raw_indices = typer.prompt("Enter issue numbers separated by commas (e.g. 1,3)", default="").strip()
        chosen_indices: list[int] = []
        for token in raw_indices.split(","):
            token = token.strip()
            if token.isdigit():
                num = int(token)
                if 1 <= num <= len(fixable) and num not in chosen_indices:
                    chosen_indices.append(num)
        if not chosen_indices:
            console.print("[yellow]No valid issue numbers selected; skipping remediation.[/yellow]")
            return html_path
        selected = [fixable[i - 1] for i in chosen_indices]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task(f"Applying {len(selected)} selected remediation(s)...", total=None)
        try:
            run_remediation(
                report=report,
                config=cfg,
                config_path=config_path,
                output_dir=output_dir,
                dry_run=False,
                selected_findings=selected,
                auto_approve=True,
                console=console,
            )
        finally:
            progress.remove_task(task_id)

    updated_html, updated_pdf = generate_report(
        report=report,
        output_dir=output_dir,
        generate_pdf=export_pdf,
        console=console,
    )
    console.print()
    console.print(f"[bold green]Updated HTML report saved:[/bold green] {updated_html.resolve()}")
    if updated_pdf is not None:
        console.print(f"[bold green]Updated PDF report saved:[/bold green]  {updated_pdf.resolve()}")
    return updated_html


@app.command("scan")
def scan(
    config: Path = typer.Option(
        Path("config.yaml"),
        "--config",
        "-c",
        help="Path to the YAML configuration file.",
    ),
    pdf: bool = typer.Option(
        False,
        "--pdf",
        help="Export a PDF report alongside the standalone HTML report.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Override output directory for generated reports.",
    ),
    fix: bool = typer.Option(
        False,
        "--fix",
        help="Interactively review and apply safe automated fixes for detected issues.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview safe remediation commands/API calls without making changes.",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Skip the interactive remediation menu after report generation.",
    ),
) -> Path:
    """Run enabled security audit modules and generate HTML/PDF reports."""
    cfg = _load_config(config)
    general_cfg = cfg.get("general") or {}
    output_dir = output or Path(str(general_cfg.get("output_dir") or "./reports"))
    export_pdf = pdf or bool(general_cfg.get("generate_pdf", False))

    hostname = socket.gethostname()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report = AuditReport(timestamp=timestamp, hostname=hostname)

    console.print(
        Panel.fit(
            f"[bold cyan]AEGISINFRA[/bold cyan] [dim]| Infrastructure Security Auditor[/dim]\n"
            f"Target Host: [bold white]{hostname}[/bold white]  •  Config: [bold white]{config}[/bold white]",
            border_style="bright_cyan",
        )
    )

    modules = (
        ("Network & Port Scan", run_network_scan, cfg.get("network") or {}),
        ("Docker Security Audit", run_docker_audit, cfg.get("docker") or {}),
        ("Proxmox VE Audit", run_proxmox_audit, cfg.get("proxmox") or {}),
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        for label, runner, module_cfg in modules:
            task_id = progress.add_task(f"Running {label}...", total=None)
            try:
                module_findings: list[Finding] = runner(module_cfg, console=console)
                for item in module_findings:
                    report.add_finding(item)
            except Exception as exc:
                console.print(f"[yellow]Warning: {label} encountered an unexpected error: {exc}[/yellow]")
            finally:
                progress.remove_task(task_id)

    _render_terminal_summary(report)

    html_path, pdf_path = generate_report(
        report=report,
        output_dir=output_dir,
        generate_pdf=export_pdf,
        console=console,
    )

    console.print()
    console.print(f"[bold green]HTML report saved:[/bold green] {html_path.resolve()}")
    if pdf_path is not None:
        console.print(f"[bold green]PDF report saved:[/bold green]  {pdf_path.resolve()}")

    is_interactive = (
        sys.stdin is not None
        and sys.stdin.isatty()
        and not os.environ.get("CI")
        and not non_interactive
    )

    if fix or dry_run:
        run_remediation(
            report=report,
            config=cfg,
            config_path=config,
            output_dir=output_dir,
            dry_run=dry_run,
            console=console,
        )
        html_path, pdf_path = generate_report(
            report=report,
            output_dir=output_dir,
            generate_pdf=export_pdf,
            console=console,
        )
        console.print()
        console.print(f"[bold green]Updated HTML report saved:[/bold green] {html_path.resolve()}")
        if pdf_path is not None:
            console.print(f"[bold green]Updated PDF report saved:[/bold green]  {pdf_path.resolve()}")
    elif is_interactive:
        html_path = _prompt_interactive_remediation(
            report=report,
            cfg=cfg,
            config_path=config,
            output_dir=output_dir,
            export_pdf=export_pdf,
            html_path=html_path,
        )

    return html_path


if __name__ == "__main__":
    app()
