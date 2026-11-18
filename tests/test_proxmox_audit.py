"""Unit tests for scanner/proxmox_audit.py."""

from unittest.mock import MagicMock, patch

from rich.console import Console

from models import Severity
from scanner.proxmox_audit import run_proxmox_audit


def test_proxmox_audit_detects_privileged_lxc_nesting_and_disabled_firewalls() -> None:
    proxmox = MagicMock()
    proxmox.nodes.get.return_value = [{"node": "pve1"}]
    proxmox.cluster.firewall.options.get.return_value = {"enable": 0}
    proxmox.access.users.get.return_value = [{"userid": "audit@pve"}]
    proxmox.access.users.return_value.token.get.return_value = [
        {"tokenid": "aegis", "privsep": 0}
    ]

    node_mock = MagicMock()
    node_mock.firewall.options.get.return_value = {"enable": 0}
    node_mock.lxc.get.return_value = [{"vmid": 100, "name": "priv-ct"}]
    node_mock.lxc.return_value.config.get.return_value = {
        "unprivileged": 0,
        "features": "nesting=1",
        "net0": "name=eth0,bridge=vmbr0",
    }
    node_mock.qemu.get.return_value = [{"vmid": 101, "name": "db-vm"}]
    node_mock.qemu.return_value.config.get.return_value = {
        "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1"
    }
    proxmox.nodes.return_value = node_mock

    cfg = {
        "enabled": True,
        "host": "192.0.2.10",
        "port": 8006,
        "user": "audit@pve",
        "token_name": "aegis",
        "token_value": "fake-secret",
        "verify_ssl": False,
    }

    with patch("proxmoxer.ProxmoxAPI", return_value=proxmox):
        findings = run_proxmox_audit(cfg, console=Console(quiet=True))

    titles = {f.title: f.severity for f in findings}
    assert titles["Privileged LXC Container"] == Severity.HIGH
    assert titles["Risky Features Enabled on Privileged LXC Container"] == Severity.HIGH
    assert titles["Datacenter Firewall Disabled"] == Severity.MEDIUM
    assert titles["Proxmox Node Firewall Disabled"] == Severity.MEDIUM
    assert titles["LXC Network Interface Firewall Disabled"] == Severity.MEDIUM
    assert titles["API Token Without Privilege Separation (privsep=0)"] == Severity.MEDIUM
    assert "QEMU VM Network Interface Firewall Disabled" not in titles
