"""AegisInfra CLI entry point."""

from __future__ import annotations

import os
import shutil
import socket
import stat
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
        style = _SEVERITY_STYLES.get(finding.severity, "white")
        findings_table.add_row(
            f"[{style}]{finding.severity.value}[/{style}]",
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
            f"[bold cyan]AegisInfra Security Audit[/bold cyan]\n"
            f"Host: [bold]{hostname}[/bold] | Config: [bold]{config}[/bold]",
            border_style="cyan",
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
    return html_path


if __name__ == "__main__":
    app()
