"""Unified entry-point script for AegisInfra lifecycle: setup, verification, tests, and audit."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import shutil
import sys
import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from healthcheck import (
    CheckResult,
    _check_python_version,
    _check_required_packages,
    _check_weasyprint,
    _run_mocked_e2e,
)
from main import _load_config, scan as run_real_scan

_BASE_DIR = Path(__file__).resolve().parent
console = Console()

app = typer.Typer(
    name="aegisinfra-start",
    help="Unified AegisInfra runner: auto-setup, self-checks, pytest suite, and security audit.",
    add_completion=False,
    pretty_exceptions_show_locals=False,
)


def _print_check_line(result: CheckResult) -> None:
    """Print a single clean status line for a verification check."""
    tag_map = {
        "PASS": "[bold green][PASS][/bold green]",
        "WARN": "[bold yellow][WARN][/bold yellow]",
        "FAIL": "[bold red][FAIL][/bold red]",
    }
    tag = tag_map.get(result.status, "[white][INFO][/white]")
    console.print(f"  {tag} {result.name}: [dim]{result.detail}[/dim]")


def _auto_setup(config_path: Path) -> None:
    """Create config.yaml from config.example.yaml if using the default path and missing."""
    if config_path.exists():
        return

    example_path = _BASE_DIR / "config.example.yaml"
    if config_path.name == "config.yaml" and example_path.exists():
        shutil.copy2(example_path, config_path)
        console.print(
            f"[bold yellow]Notice:[/bold yellow] '{config_path}' was not found; "
            f"created it automatically from '{example_path.name}'."
        )
        return

    console.print(f"[red]Error: Configuration file '{config_path}' not found.[/red]")
    raise typer.Exit(code=1)


def _run_self_checks(config_path: Path) -> None:
    """Run environment, dependency, config, XSS dry-run, and pytest checks."""
    console.print("[bold cyan]Step 1/2: Running self-checks & security verification...[/bold cyan]")

    checks: list[CheckResult] = [_check_python_version(), *_check_required_packages()]
    weasy_res, _ = _check_weasyprint()
    checks.append(weasy_res)

    for res in checks:
        _print_check_line(res)
        if res.status == "FAIL":
            console.print(f"\n[bold red]Aborting:[/bold red] Critical check failed ({res.name}).")
            raise typer.Exit(code=1)

    _load_config(config_path)
    _print_check_line(CheckResult("Config: safe_load & permissions", "PASS", f"Loaded '{config_path}' safely"))

    dry_run_res = _run_mocked_e2e(weasyprint_ok=False)
    _print_check_line(dry_run_res)
    if dry_run_res.status == "FAIL":
        console.print(f"\n[bold red]Aborting:[/bold red] {dry_run_res.detail}")
        raise typer.Exit(code=1)

    tests_dir = _BASE_DIR / "tests"
    if tests_dir.is_dir() and importlib.util.find_spec("pytest") is not None:
        import pytest

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            exit_code = pytest.main(["-q", str(tests_dir)])

        if exit_code == 0:
            _print_check_line(CheckResult("Automated Test Suite (pytest)", "PASS", "All tests passed (0 failures)"))
        else:
            _print_check_line(CheckResult("Automated Test Suite (pytest)", "FAIL", f"pytest exited with code {exit_code}"))
            console.print(buf.getvalue())
            console.print("\n[bold red]Aborting:[/bold red] Automated test suite failed.")
            raise typer.Exit(code=1)
    else:
        _print_check_line(
            CheckResult("Automated Test Suite (pytest)", "WARN", "pytest or tests/ not found; skipped")
        )


def _pause_if_interactive() -> None:
    """Pause for Enter in interactive terminals (non-CI) so double-click windows stay open."""
    if sys.stdin is not None and sys.stdin.isatty() and not os.environ.get("CI"):
        try:
            input("\nPress Enter to exit...")
        except (EOFError, KeyboardInterrupt):
            pass


@app.command()
def start(
    config: Path = typer.Option(
        Path("config.yaml"),
        "--config",
        "-c",
        help="Path to the YAML configuration file.",
    ),
    skip_checks: bool = typer.Option(
        False,
        "--skip-checks",
        help="Skip internal self-checks and the pytest suite before scanning.",
    ),
    check_only: bool = typer.Option(
        False,
        "--check-only",
        help="Run auto-setup, self-checks, and pytest without running the live audit.",
    ),
    pdf: bool = typer.Option(
        False,
        "--pdf",
        help="Export a PDF report alongside the standalone HTML report.",
    ),
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        help="Do not automatically open the generated HTML report in the default browser.",
    ),
) -> None:
    """Auto-setup config, verify environment & tests, and run the AegisInfra audit."""
    console.print(
        Panel.fit(
            "[bold cyan]AegisInfra Unified Launcher[/bold cyan]",
            border_style="cyan",
        )
    )

    _auto_setup(config)

    if not skip_checks:
        _run_self_checks(config)
        console.print()

    if check_only:
        console.print("[bold green]All verification checks passed (--check-only). Exiting.[/bold green]")
        raise typer.Exit(code=0)

    console.print("[bold cyan]Step 2/2: Executing live infrastructure audit...[/bold cyan]\n")
    html_path = run_real_scan(config=config, pdf=pdf, output=None)

    if not no_browser and html_path is not None and html_path.exists():
        try:
            webbrowser.open(html_path.resolve().as_uri())
            console.print("[dim]Opened HTML report in your default web browser.[/dim]")
        except Exception as exc:
            console.print(f"[yellow]Warning: Could not open browser automatically ({exc}).[/yellow]")


if __name__ == "__main__":
    exit_code = 0
    try:
        app(standalone_mode=False)
    except typer.Exit as exc:
        exit_code = exc.exit_code
    except Exception as exc:
        console.print(f"[bold red]Unexpected error:[/bold red] {exc}")
        exit_code = 1
    finally:
        if "--help" not in sys.argv:
            _pause_if_interactive()
    sys.exit(exit_code)
