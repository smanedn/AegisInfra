"""Unit tests for scanner/network.py."""

import socket
from unittest.mock import MagicMock, patch

from rich.console import Console

from models import Severity
from scanner.network import run_network_scan


def test_network_scan_classifies_ports_and_handles_timeouts() -> None:
    def fake_create_connection(address: tuple[str, int], timeout: float = 1.5) -> MagicMock:
        _host, port = address
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.__exit__.return_value = False

        if port == 2375:
            sock.recv.return_value = b'{"ApiVersion":"1.45"}'
            return sock
        if port == 80:
            sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx"
            return sock
        if port == 22:
            sock.recv.return_value = b"SSH-2.0-OpenSSH_9.6"
            return sock
        if port == 443:
            raise socket.timeout("timed out")
        raise OSError("Connection refused")

    cfg = {
        "enabled": True,
        "targets": ["127.0.0.1"],
        "ports": [22, 80, 443, 2375, 9999],
        "timeout": 0.5,
        "max_workers": 4,
    }

    with patch("scanner.network.socket.create_connection", side_effect=fake_create_connection):
        findings = run_network_scan(cfg, console=Console(quiet=True))

    by_target = {f.target: f for f in findings}
    assert "127.0.0.1:443" not in by_target
    assert "127.0.0.1:9999" not in by_target

    assert by_target["127.0.0.1:2375"].severity == Severity.CRITICAL
    assert "ApiVersion" in by_target["127.0.0.1:2375"].description

    assert by_target["127.0.0.1:80"].severity == Severity.MEDIUM
    assert "nginx" in by_target["127.0.0.1:80"].description

    assert by_target["127.0.0.1:22"].severity == Severity.INFO
    assert "OpenSSH_9.6" in by_target["127.0.0.1:22"].description
