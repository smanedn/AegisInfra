"""Network and TCP port scanner with non-intrusive banner grabbing."""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

from rich.console import Console

from models import Finding, Severity

_HTTP_PROBE_PORTS = frozenset({80, 3000, 8000, 8080, 9000, 9090})


@dataclass(frozen=True, slots=True)
class _PortRule:
    service: str
    severity: Severity
    title: str
    description: str
    remediation: str


# Data-driven port risk classification
_PORT_RULES: dict[int, _PortRule] = {
    2375: _PortRule(
        service="Docker Daemon (Unencrypted)",
        severity=Severity.CRITICAL,
        title="Unauthenticated Docker Daemon API Exposed",
        description=(
            "Port 2375 exposes the Docker Engine API over unencrypted HTTP without TLS "
            "authentication, allowing full remote root-equivalent host takeover."
        ),
        remediation=(
            "Disable TCP binding on port 2375 immediately. Use a local Unix socket or "
            "configure mutual TLS (mTLS) on port 2376 restricted to trusted management IPs."
        ),
    ),
    23: _PortRule(
        service="Telnet",
        severity=Severity.CRITICAL,
        title="Insecure Telnet Service Exposed",
        description=(
            "Port 23 (Telnet) transmits all credentials and session data in cleartext, "
            "leaving it vulnerable to eavesdropping and credential interception."
        ),
        remediation="Disable the Telnet daemon and migrate remote administration to SSH (port 22) with key-based auth.",
    ),
    6379: _PortRule(
        service="Redis",
        severity=Severity.CRITICAL,
        title="Exposed Redis Instance",
        description=(
            "Port 6379 (Redis) is reachable over the network. By default Redis lacks "
            "authentication and encryption, which can lead to data exfiltration or RCE."
        ),
        remediation=(
            "Bind Redis to 127.0.0.1 in redis.conf, enable requirepass/ACL authentication, "
            "and block port 6379 at the host firewall."
        ),
    ),
    27017: _PortRule(
        service="MongoDB",
        severity=Severity.HIGH,
        title="Exposed MongoDB Database Port",
        description=(
            "Port 27017 (MongoDB) is accessible over the network, increasing the risk of "
            "unauthorized database access or ransomware if authentication is misconfigured."
        ),
        remediation=(
            "Bind MongoDB to localhost or a private management interface, enforce SCRAM "
            "authentication, and restrict access with firewall rules."
        ),
    ),
    21: _PortRule(
        service="FTP",
        severity=Severity.HIGH,
        title="Unencrypted FTP Service Exposed",
        description=(
            "Port 21 (FTP) transmits usernames, passwords, and file transfers in plaintext."
        ),
        remediation="Replace FTP with SFTP (over SSH) or FTPS (FTP over explicit TLS).",
    ),
    139: _PortRule(
        service="NetBIOS",
        severity=Severity.HIGH,
        title="Legacy NetBIOS Session Service Exposed",
        description=(
            "Port 139 (NetBIOS) is open, which can leak host information and expose legacy "
            "file-sharing attack surfaces."
        ),
        remediation="Disable NetBIOS over TCP/IP if unused, or restrict access to trusted LAN segments via firewall.",
    ),
    445: _PortRule(
        service="SMB",
        severity=Severity.HIGH,
        title="SMB File Sharing Port Exposed",
        description=(
            "Port 445 (SMB) is reachable. Exposed SMB services are frequent targets for "
            "brute-force, relay, and lateral movement attacks."
        ),
        remediation=(
            "Restrict port 445 to trusted internal subnets via firewall, disable SMBv1, "
            "and enforce SMB signing."
        ),
    ),
    111: _PortRule(
        service="RPCbind",
        severity=Severity.HIGH,
        title="RPCbind / Portmapper Exposed",
        description=(
            "Port 111 (rpcbind) is open and can be abused for network enumeration or "
            "UDP amplification attacks if exposed externally."
        ),
        remediation="Disable rpcbind if NFS/NIS is not required, or restrict port 111 to trusted hosts.",
    ),
    5900: _PortRule(
        service="VNC",
        severity=Severity.HIGH,
        title="Unencrypted VNC Remote Desktop Exposed",
        description=(
            "Port 5900 (VNC) is open. Standard VNC uses weak authentication and lacks "
            "transport encryption by default."
        ),
        remediation="Tunnel VNC over SSH or a VPN, and bind the VNC server to 127.0.0.1.",
    ),
    25: _PortRule(
        service="SMTP",
        severity=Severity.MEDIUM,
        title="SMTP Mail Transfer Port Open",
        description=(
            "Port 25 (SMTP) is reachable. Misconfigured relays can allow spam abuse or "
            "unencrypted mail submission."
        ),
        remediation="Ensure open relay is disabled, enforce STARTTLS, and restrict port 25 if not a public MX.",
    ),
    80: _PortRule(
        service="HTTP",
        severity=Severity.MEDIUM,
        title="Unencrypted HTTP Service Exposed",
        description="Port 80 (HTTP) serves traffic in plaintext without TLS encryption.",
        remediation="Redirect all HTTP traffic to HTTPS (port 443) using valid TLS certificates.",
    ),
    8080: _PortRule(
        service="HTTP-Alt",
        severity=Severity.MEDIUM,
        title="Unencrypted Alternate HTTP Service Exposed",
        description="Port 8080 serves unencrypted HTTP traffic, often used by admin panels or proxies.",
        remediation="Place the service behind an HTTPS reverse proxy and bind the upstream port to 127.0.0.1.",
    ),
    3000: _PortRule(
        service="HTTP-App",
        severity=Severity.MEDIUM,
        title="Unencrypted Web Application Port Exposed",
        description="Port 3000 is open and commonly serves unencrypted web dashboards or APIs.",
        remediation="Bind the application to 127.0.0.1 and expose it only through a TLS-terminating reverse proxy.",
    ),
    9000: _PortRule(
        service="HTTP-Admin",
        severity=Severity.MEDIUM,
        title="Unencrypted Management Port Exposed",
        description="Port 9000 is open (commonly Portainer or admin interfaces) without transport encryption.",
        remediation="Restrict access to localhost/VPN and terminate TLS in front of the service.",
    ),
    3306: _PortRule(
        service="MySQL/MariaDB",
        severity=Severity.MEDIUM,
        title="Exposed MySQL/MariaDB Database Port",
        description=(
            "Port 3306 is reachable over the network, exposing the database to brute-force "
            "and vulnerability exploitation."
        ),
        remediation="Bind MySQL/MariaDB to 127.0.0.1 or a private backend network and enforce TLS connections.",
    ),
    5432: _PortRule(
        service="PostgreSQL",
        severity=Severity.MEDIUM,
        title="Exposed PostgreSQL Database Port",
        description=(
            "Port 5432 is reachable over the network, increasing exposure to credential "
            "attacks and unauthorized queries."
        ),
        remediation="Restrict listen_addresses to 127.0.0.1, tighten pg_hba.conf rules, and require SSL.",
    ),
    22: _PortRule(
        service="SSH",
        severity=Severity.INFO,
        title="SSH Service Detected",
        description="Port 22 (SSH) is open for remote administration.",
        remediation=(
            "Verify PasswordAuthentication is disabled in sshd_config, permit key-based "
            "authentication only, and consider Fail2Ban or firewall allowlisting."
        ),
    ),
    443: _PortRule(
        service="HTTPS",
        severity=Severity.INFO,
        title="HTTPS Service Detected",
        description="Port 443 (HTTPS) is open and serving TLS-encrypted traffic.",
        remediation="Ensure strong TLS 1.2/1.3 ciphers are configured and certificates are kept up to date.",
    ),
    8443: _PortRule(
        service="HTTPS-Alt",
        severity=Severity.INFO,
        title="Alternate HTTPS Service Detected",
        description="Port 8443 is open for TLS-encrypted web or management traffic.",
        remediation="Verify valid TLS certificates and restrict administrative access to trusted IPs.",
    ),
    8006: _PortRule(
        service="Proxmox VE Web UI",
        severity=Severity.INFO,
        title="Proxmox VE Management Interface Detected",
        description="Port 8006 (Proxmox VE Web UI) is reachable on the network.",
        remediation="Restrict port 8006 to a dedicated management VLAN or VPN and enable 2FA for all users.",
    ),
    2376: _PortRule(
        service="Docker Daemon (TLS)",
        severity=Severity.INFO,
        title="TLS-Enabled Docker Daemon Port Detected",
        description="Port 2376 (Docker TLS) is open.",
        remediation="Confirm mutual TLS (--tlsverify) is strictly enforced and restrict source IPs.",
    ),
    53: _PortRule(
        service="DNS",
        severity=Severity.INFO,
        title="DNS Service Detected",
        description="Port 53 (TCP DNS) is open.",
        remediation="Ensure recursive queries are restricted to internal clients to prevent DNS amplification.",
    ),
}


def _expand_targets(raw_targets: list[str], console: Console) -> list[str]:
    """Expand IP addresses and CIDR ranges into a deduplicated list of host strings."""
    hosts: list[str] = []
    seen: set[str] = set()

    for entry in raw_targets:
        text = str(entry).strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
            if network.num_addresses == 1:
                ip_str = str(network.network_address)
                if ip_str not in seen:
                    seen.add(ip_str)
                    hosts.append(ip_str)
            else:
                for addr in network.hosts():
                    ip_str = str(addr)
                    if ip_str not in seen:
                        seen.add(ip_str)
                        hosts.append(ip_str)
        except ValueError:
            # Support hostnames if provided instead of IPs/CIDRs
            if text not in seen:
                seen.add(text)
                hosts.append(text)
                console.print(f"[dim]Scanning hostname target: {text}[/dim]")

    return hosts


def _sanitize_banner(raw: bytes, max_len: int = 160) -> str:
    """Decode and sanitize a service banner for safe display."""
    text = raw.decode("utf-8", errors="replace")
    cleaned = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in text).strip()
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > max_len:
        return f"{cleaned[:max_len - 3]}..."
    return cleaned


def _grab_banner(sock: socket.socket, host: str, port: int, timeout: float) -> str:
    """Perform non-intrusive banner grabbing on an already-connected socket."""
    banner_timeout = max(0.1, min(timeout, 1.0))
    try:
        sock.settimeout(banner_timeout)
        data = sock.recv(1024)
        if data:
            return _sanitize_banner(data)
    except (socket.timeout, OSError):
        pass

    if port in _HTTP_PROBE_PORTS:
        try:
            sock.settimeout(banner_timeout)
            probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: AegisInfra\r\n\r\n"
            sock.sendall(probe.encode("ascii"))
            data = sock.recv(1024)
            if data:
                first_line = data.split(b"\r\n", 1)[0]
                server_header = next(
                    (
                        line
                        for line in data.split(b"\r\n")
                        if line.lower().startswith(b"server:")
                    ),
                    b"",
                )
                combined = first_line + (b" | " + server_header if server_header else b"")
                return _sanitize_banner(combined)
        except (socket.timeout, OSError):
            pass

    return ""


def _scan_port(host: str, port: int, timeout: float) -> tuple[str, int, str] | None:
    """Check if a TCP port is open and return (host, port, banner) or None."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = _grab_banner(sock, host, port, timeout)
            return (host, port, banner)
    except (socket.timeout, OSError):
        return None


def _build_finding(host: str, port: int, banner: str) -> Finding:
    """Create a Finding from an open port and optional banner."""
    target = f"{host}:{port}"
    rule = _PORT_RULES.get(port)
    banner_note = f" Banner: `{banner}`." if banner else ""

    if rule is not None:
        return Finding(
            category="Network",
            target=target,
            title=rule.title,
            description=f"{rule.description}{banner_note}",
            severity=rule.severity,
            remediation=rule.remediation,
        )

    return Finding(
        category="Network",
        target=target,
        title=f"Open TCP Port {port}",
        description=f"TCP port {port} is open and accepting connections.{banner_note}",
        severity=Severity.INFO,
        remediation="Verify this service is intentionally exposed and protected by firewall rules.",
    )


def run_network_scan(
    config: dict[str, Any],
    console: Console | None = None,
) -> list[Finding]:
    """Scan configured IPs/CIDR subnets and TCP ports concurrently.

    Args:
        config: The ``network`` section from the AegisInfra configuration.
        console: Optional Rich console for status/warning output.

    Returns:
        A list of discovered network security findings.
    """
    out = console or Console()
    if not config.get("enabled", True):
        return []

    raw_targets = config.get("targets") or []
    raw_ports = config.get("ports") or []
    timeout = max(0.1, min(float(config.get("timeout", 1.5)), 30.0))
    max_workers = max(1, int(config.get("max_workers", 50)))

    hosts = _expand_targets(raw_targets, out)
    ports = sorted({int(p) for p in raw_ports if 1 <= int(p) <= 65535})

    if not hosts or not ports:
        out.print("[yellow]Warning: Network scan skipped (no valid targets or ports configured).[/yellow]")
        return []

    findings: list[Finding] = []
    tasks = [(host, port) for host in hosts for port in ports]
    worker_count = min(max_workers, len(tasks))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(_scan_port, host, port, timeout): (host, port)
            for host, port in tasks
        }
        for future in as_completed(future_map):
            try:
                result = future.result()
                if result is not None:
                    host, port, banner = result
                    findings.append(_build_finding(host, port, banner))
            except Exception as exc:
                host, port = future_map[future]
                out.print(f"[yellow]Warning: Error scanning {host}:{port}: {exc}[/yellow]")

    return findings
