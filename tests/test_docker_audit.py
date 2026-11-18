"""Unit tests for scanner/docker_audit.py."""

from unittest.mock import MagicMock, patch

from docker.errors import DockerException
from rich.console import Console

from models import Severity
from scanner.docker_audit import run_docker_audit


def test_docker_audit_detects_privileged_mounts_and_wildcard_ports() -> None:
    container = MagicMock()
    container.name = "web-app"
    container.short_id = "abc1234"
    container.attrs = {
        "HostConfig": {
            "Privileged": True,
            "NetworkMode": "bridge",
            "PidMode": "bridge",
            "Binds": ["/var/run/docker.sock:/var/run/docker.sock"],
        },
        "Config": {"User": "1000:1000"},
        "Mounts": [],
        "NetworkSettings": {
            "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
        },
    }

    client = MagicMock()
    client.ping.return_value = True
    client.containers.list.return_value = [container]
    client.images.list.return_value = []

    cfg = {
        "enabled": True,
        "socket_url": "unix:///var/run/docker.sock",
        "include_stopped": False,
        "max_image_age_days": 90,
    }

    with patch("docker.DockerClient", return_value=client):
        findings = run_docker_audit(cfg, console=Console(quiet=True))

    titles_to_sev = {f.title: f.severity for f in findings}
    assert titles_to_sev["Container Running in Privileged Mode"] == Severity.CRITICAL
    assert titles_to_sev["Sensitive Host Path Mounted (/var/run/docker.sock)"] == Severity.HIGH
    assert titles_to_sev["Container Ports Bound to All Interfaces (0.0.0.0)"] == Severity.MEDIUM


def test_docker_audit_handles_unreachable_daemon_gracefully() -> None:
    cfg = {"enabled": True, "socket_url": "unix:///var/run/docker.sock"}

    with patch("docker.DockerClient", side_effect=DockerException("daemon unreachable")):
        findings = run_docker_audit(cfg, console=Console(quiet=True))

    assert findings == []
