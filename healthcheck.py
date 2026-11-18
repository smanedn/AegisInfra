"""Standalone self-contained verification runner for AegisInfra."""

from __future__ import annotations

import importlib
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

_BASE_DIR = Path(__file__).resolve().parent
if str(_BASE_DIR) not in sys.path:
    sys.path.insert(0, str(_BASE_DIR))


@dataclass(slots=True)
class CheckResult:
    """Represents the outcome of a single healthcheck step."""

    name: str
    status: str  # "PASS", "WARN", "FAIL"
    detail: str


def _check_python_version() -> CheckResult:
    ver = sys.version_info
    ver_str = f"{ver.major}.{ver.minor}.{ver.micro}"
    if ver >= (3, 11):
        return CheckResult("Python Version (>= 3.11)", "PASS", f"Python {ver_str}")
    return CheckResult("Python Version (>= 3.11)", "FAIL", f"Found Python {ver_str}, require >= 3.11")


def _check_required_packages() -> list[CheckResult]:
    results: list[CheckResult] = []
    required = ("typer", "rich", "yaml", "docker", "proxmoxer", "requests", "jinja2")
    for pkg in required:
        try:
            importlib.import_module(pkg)
            results.append(CheckResult(f"Dependency: {pkg}", "PASS", "Imported cleanly"))
        except Exception as exc:
            results.append(CheckResult(f"Dependency: {pkg}", "FAIL", f"Import failed: {exc}"))
    return results


def _check_weasyprint() -> tuple[CheckResult, bool]:
    try:
        import weasyprint  # type: ignore[import-untyped]

        _ = weasyprint.__version__
        return CheckResult("Optional: weasyprint", "PASS", "Available with system libraries"), True
    except (ImportError, OSError) as exc:
        return (
            CheckResult(
                "Optional: weasyprint",
                "WARN",
                f"Unavailable ({exc}); PDF export will gracefully fall back to HTML-only",
            ),
            False,
        )


def _check_config_template() -> CheckResult:
    cfg_path = _BASE_DIR / "config.example.yaml"
    if not cfg_path.exists():
        return CheckResult("Config: config.example.yaml", "FAIL", "File not found")

    try:
        import yaml

        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return CheckResult("Config: config.example.yaml", "FAIL", f"YAML parse error: {exc}")

    if not isinstance(data, dict):
        return CheckResult("Config: config.example.yaml", "FAIL", "Top-level YAML is not a mapping")

    expected_sections = {
        "general": ("output_dir", "generate_pdf"),
        "network": ("enabled", "targets", "ports", "timeout", "max_workers"),
        "docker": ("enabled", "socket_url", "include_stopped", "max_image_age_days"),
        "proxmox": ("enabled", "host", "port", "user", "token_name", "token_value", "verify_ssl"),
    }

    missing: list[str] = []
    for section, keys in expected_sections.items():
        if section not in data or not isinstance(data[section], dict):
            missing.append(section)
            continue
        for key in keys:
            if key not in data[section]:
                missing.append(f"{section}.{key}")

    if missing:
        return CheckResult(
            "Config: config.example.yaml",
            "FAIL",
            f"Missing expected keys: {', '.join(missing)}",
        )
    return CheckResult("Config: config.example.yaml", "PASS", "Valid YAML with all expected sections & keys")


def _check_module_imports() -> list[CheckResult]:
    modules = (
        "models",
        "scanner",
        "scanner.network",
        "scanner.docker_audit",
        "scanner.proxmox_audit",
        "reporter",
        "reporter.generator",
        "main",
    )
    results: list[CheckResult] = []
    for mod in modules:
        try:
            importlib.import_module(mod)
            results.append(CheckResult(f"Module: {mod}", "PASS", "Imported cleanly"))
        except Exception as exc:
            results.append(CheckResult(f"Module: {mod}", "FAIL", f"Import error: {exc}"))
    return results


def _build_mock_docker_client() -> MagicMock:
    container = MagicMock()
    container.name = "evil-<img src=x onerror=alert(1)>"
    container.short_id = "deadbeef1234"
    container.attrs = {
        "HostConfig": {
            "Privileged": True,
            "NetworkMode": "host",
            "PidMode": "bridge",
            "Binds": ["/var/run/docker.sock:/var/run/docker.sock"],
            "PortBindings": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
        },
        "Config": {"User": ""},
        "Mounts": [],
        "NetworkSettings": {
            "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
        },
    }

    image = MagicMock()
    image.tags = ["vulnerable-app:latest"]
    image.short_id = "img123456"
    image.attrs = {"Created": "2020-01-01T00:00:00Z"}

    client = MagicMock()
    client.ping.return_value = True
    client.containers.list.return_value = [container]
    client.images.list.return_value = [image]
    return client


def _build_mock_proxmox_client() -> MagicMock:
    proxmox = MagicMock()
    proxmox.nodes.get.return_value = [{"node": "pve1"}]
    proxmox.cluster.firewall.options.get.return_value = {"enable": 0}
    proxmox.access.users.get.return_value = [{"userid": "audit@pve"}]
    proxmox.access.users.return_value.token.get.return_value = [
        {"tokenid": "aegis-token", "privsep": 0}
    ]

    node_mock = MagicMock()
    node_mock.firewall.options.get.return_value = {"enable": 0}
    node_mock.lxc.get.return_value = [{"vmid": 100, "name": "priv-ct"}]
    node_mock.lxc.return_value.config.get.return_value = {
        "unprivileged": 0,
        "features": "nesting=1,keyctl=1",
        "net0": "name=eth0,bridge=vmbr0",
    }
    node_mock.qemu.get.return_value = [{"vmid": 101, "name": "web-vm"}]
    node_mock.qemu.return_value.config.get.return_value = {
        "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
    }
    proxmox.nodes.return_value = node_mock
    return proxmox


def _run_mocked_e2e(weasyprint_ok: bool) -> CheckResult:
    try:
        from rich.console import Console

        from models import AuditReport
        from reporter.generator import generate_report
        from scanner.docker_audit import run_docker_audit
        from scanner.network import run_network_scan
        from scanner.proxmox_audit import run_proxmox_audit
    except Exception as exc:
        return CheckResult("E2E Mocked Dry Run", "FAIL", f"Missing required modules: {exc}")

    xss_banner = "<script>alert('xss')</script>"
    xss_container = "<img src=x onerror=alert(1)>"
    silent_console = Console(quiet=True)

    def fake_create_connection(address: tuple[str, int], timeout: float = 1.5) -> MagicMock:
        _host, port = address
        if port == 80:
            sock = MagicMock()
            sock.__enter__.return_value = sock
            sock.__exit__.return_value = False
            sock.recv.return_value = f"{xss_banner} HTTP/1.1 200 OK".encode("utf-8")
            return sock
        raise OSError("Connection refused")

    mock_docker_client = _build_mock_docker_client()
    mock_proxmox_client = _build_mock_proxmox_client()

    try:
        with (
            patch("scanner.network.socket.create_connection", side_effect=fake_create_connection),
            patch("docker.DockerClient", return_value=mock_docker_client),
            patch("proxmoxer.ProxmoxAPI", return_value=mock_proxmox_client),
        ):
            net_findings = run_network_scan(
                {"enabled": True, "targets": ["127.0.0.1"], "ports": [80, 443], "timeout": 0.5, "max_workers": 4},
                console=silent_console,
            )
            docker_findings = run_docker_audit(
                {"enabled": True, "socket_url": "unix:///var/run/docker.sock", "include_stopped": False, "max_image_age_days": 90},
                console=silent_console,
            )
            proxmox_findings = run_proxmox_audit(
                {
                    "enabled": True,
                    "host": "127.0.0.1",
                    "port": 8006,
                    "user": "audit@pve",
                    "token_name": "aegis-token",
                    "token_value": "secret-token-value",
                    "verify_ssl": False,
                },
                console=silent_console,
            )

        report = AuditReport(timestamp="2026-01-01 00:00:00 UTC", hostname="healthcheck-host")
        for finding in [*net_findings, *docker_findings, *proxmox_findings]:
            report.add_finding(finding)

        categories = {f.category for f in report.findings}
        if not {"Network", "Docker", "Proxmox"}.issubset(categories):
            return CheckResult(
                "E2E Mocked Dry Run",
                "FAIL",
                f"Expected Network, Docker, Proxmox findings; got {sorted(categories)}",
            )

        with tempfile.TemporaryDirectory() as tmp_dir:
            html_path, pdf_path = generate_report(
                report=report,
                output_dir=tmp_dir,
                generate_pdf=weasyprint_ok,
                console=silent_console,
            )

            if not html_path.exists() or html_path.stat().st_size == 0:
                return CheckResult("E2E Mocked Dry Run", "FAIL", "HTML report was not generated or is empty")

            html_content = html_path.read_text(encoding="utf-8")
            if xss_banner in html_content or xss_container in html_content:
                return CheckResult("E2E Mocked Dry Run", "FAIL", "Unescaped XSS payload detected in HTML output")

            if "&lt;script&gt;" not in html_content or "&lt;img src=x onerror=alert(1)&gt;" not in html_content:
                return CheckResult("E2E Mocked Dry Run", "FAIL", "Expected escaped XSS payloads not found in HTML output")

            if weasyprint_ok:
                if pdf_path is None or not pdf_path.exists() or pdf_path.stat().st_size == 0:
                    return CheckResult("E2E Mocked Dry Run", "FAIL", "PDF report was not generated or is empty")

        pdf_note = " + PDF verified" if weasyprint_ok else " (PDF skipped)"
        return CheckResult(
            "E2E Mocked Dry Run",
            "PASS",
            f"{len(report.findings)} findings rendered; HTML{pdf_note}; XSS escaping verified",
        )
    except Exception as exc:
        return CheckResult("E2E Mocked Dry Run", "FAIL", f"Unexpected error: {exc}")


def _print_results(results: list[CheckResult]) -> None:
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title="AegisInfra Healthcheck Summary", show_lines=True, header_style="bold cyan")
        table.add_column("Check", style="bold")
        table.add_column("Status", width=8, justify="center")
        table.add_column("Details")

        style_map = {
            "PASS": "bold green",
            "WARN": "bold yellow",
            "FAIL": "bold red",
        }
        for res in results:
            style = style_map.get(res.status, "white")
            table.add_row(res.name, f"[{style}]{res.status}[/{style}]", res.detail)

        console.print(table)
    except Exception:
        for res in results:
            print(f"[{res.status}] {res.name}: {res.detail}")


def main() -> int:
    """Run all healthcheck stages and return 0 if healthy or 1 on critical failure."""
    results: list[CheckResult] = []

    results.append(_check_python_version())
    results.extend(_check_required_packages())

    weasy_result, weasy_ok = _check_weasyprint()
    results.append(weasy_result)

    results.append(_check_config_template())
    results.extend(_check_module_imports())
    results.append(_run_mocked_e2e(weasy_ok))

    _print_results(results)

    has_failure = any(res.status == "FAIL" for res in results)
    return 1 if has_failure else 0


if __name__ == "__main__":
    sys.exit(main())
