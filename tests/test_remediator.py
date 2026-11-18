"""Unit tests for remediator/fixer.py."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from rich.console import Console

from models import AuditReport, Finding, Severity
from remediator.fixer import run_remediation
from reporter.generator import generate_report


def _sample_report() -> AuditReport:
    report = AuditReport(timestamp="2026-01-01 00:00:00 UTC", hostname="test-node")
    report.add_finding(
        Finding(
            category="Docker",
            target="web-app",
            title="Wildcard Port",
            description="0.0.0.0:8080->80/tcp",
            severity=Severity.MEDIUM,
            remediation="Bind to 127.0.0.1",
            fix_id="docker.wildcard_port",
            fix_description="Generate docker-compose.override.yml",
        )
    )
    report.add_finding(
        Finding(
            category="Docker",
            target="old-img:latest",
            title="Outdated Image",
            description="Built 120 days ago",
            severity=Severity.LOW,
            remediation="Prune or rebuild",
            fix_id="docker.prune_images",
            fix_description="Prune dangling images",
        )
    )
    report.add_finding(
        Finding(
            category="Proxmox",
            target="Datacenter",
            title="Datacenter Firewall Disabled",
            description="Disabled",
            severity=Severity.MEDIUM,
            remediation="Enable firewall",
            fix_id="proxmox.cluster_firewall",
            fix_description="Enable Datacenter firewall",
        )
    )
    report.add_finding(
        Finding(
            category="Proxmox",
            target="lxc/100 (ct1) [net0]",
            title="LXC Network Interface Firewall Disabled",
            description="Missing firewall=1",
            severity=Severity.MEDIUM,
            remediation="Enable firewall=1",
            fix_id="proxmox.guest_firewall",
            fix_description="Enable firewall=1 on net0",
        )
    )
    return report


def test_remediation_dry_run_makes_no_changes(tmp_path: Path) -> None:
    report = _sample_report()
    cfg = {"general": {"output_dir": str(tmp_path)}, "docker": {}, "proxmox": {}}

    with (
        patch("remediator.fixer.typer.confirm") as mock_confirm,
        patch("docker.DockerClient") as mock_docker,
        patch("proxmoxer.ProxmoxAPI") as mock_proxmox,
    ):
        logs = run_remediation(
            report=report,
            config=cfg,
            output_dir=tmp_path,
            dry_run=True,
            console=Console(quiet=True),
        )

    assert len(logs) == 4
    assert all(log.status == "DRY_RUN" for log in logs)
    assert not (tmp_path / "docker-compose.override.yml").exists()
    mock_confirm.assert_not_called()
    mock_docker.assert_not_called()
    mock_proxmox.assert_not_called()


def test_remediation_skips_when_user_declines(tmp_path: Path) -> None:
    report = _sample_report()
    cfg = {"general": {"output_dir": str(tmp_path)}, "docker": {}, "proxmox": {}}

    with (
        patch("remediator.fixer.typer.confirm", return_value=False),
        patch("docker.DockerClient") as mock_docker,
        patch("proxmoxer.ProxmoxAPI") as mock_proxmox,
    ):
        logs = run_remediation(
            report=report,
            config=cfg,
            output_dir=tmp_path,
            dry_run=False,
            console=Console(quiet=True),
        )

    assert len(logs) == 4
    assert all(log.status == "SKIPPED" for log in logs)
    assert not (tmp_path / "docker-compose.override.yml").exists()
    mock_docker.assert_not_called()
    mock_proxmox.assert_not_called()


def test_remediation_applies_fixes_and_renders_in_report(tmp_path: Path) -> None:
    report = _sample_report()
    cfg = {
        "general": {"output_dir": str(tmp_path)},
        "docker": {"socket_url": "unix:///var/run/docker.sock"},
        "proxmox": {
            "host": "192.0.2.10",
            "port": 8006,
            "user": "audit@pve",
            "token_name": "aegis",
            "token_value": "fake",
            "verify_ssl": False,
        },
    }

    mock_docker_client = MagicMock()
    mock_docker_client.images.prune.return_value = {"SpaceReclaimed": 1024}

    mock_proxmox = MagicMock()
    mock_proxmox.nodes.get.return_value = [{"node": "pve1"}]
    mock_node = MagicMock()
    mock_node.lxc.get.return_value = [{"vmid": 100, "name": "ct1"}]
    mock_node.lxc.return_value.config.get.return_value = {"net0": "name=eth0,bridge=vmbr0"}
    mock_proxmox.nodes.return_value = mock_node

    with (
        patch("remediator.fixer.typer.confirm", return_value=True),
        patch("docker.DockerClient", return_value=mock_docker_client),
        patch("proxmoxer.ProxmoxAPI", return_value=mock_proxmox),
    ):
        logs = run_remediation(
            report=report,
            config=cfg,
            output_dir=tmp_path,
            dry_run=False,
            console=Console(quiet=True),
        )

    assert len(logs) == 4
    assert all(log.status == "APPLIED" for log in logs)
    assert (tmp_path / "docker-compose.override.yml").exists()
    mock_docker_client.images.prune.assert_called_once()
    mock_proxmox.cluster.firewall.options.put.assert_called_once_with(enable=1)
    mock_node.lxc.return_value.config.put.assert_called_once_with(
        net0="name=eth0,bridge=vmbr0,firewall=1"
    )

    html_path, _ = generate_report(report, output_dir=tmp_path, generate_pdf=False, console=Console(quiet=True))
    html = html_path.read_text(encoding="utf-8")
    assert "Applied Remediations" in html
    assert "APPLIED" in html
