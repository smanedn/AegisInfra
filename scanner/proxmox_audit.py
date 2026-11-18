"""Proxmox VE cluster, node, VM, LXC, and API token security auditor."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from models import Finding, Severity

_RISKY_LXC_FEATURES = ("nesting=1", "keyctl=1", "fuse=1", "mknod=1")


def _parse_net_interfaces(config: dict[str, Any]) -> dict[str, str]:
    """Extract netN interface definitions (e.g. net0, net1) from a guest config."""
    return {
        key: str(val)
        for key, val in config.items()
        if key.startswith("net") and key[3:].isdigit()
    }


def _has_firewall_enabled(net_value: str) -> bool:
    """Return True if a Proxmox netN string includes firewall=1."""
    parts = [part.strip().lower() for part in net_value.split(",")]
    return "firewall=1" in parts


def _audit_cluster_firewall(proxmox: Any, console: Console) -> list[Finding]:
    """Check whether the Proxmox Datacenter-level firewall is enabled."""
    findings: list[Finding] = []
    try:
        options = proxmox.cluster.firewall.options.get()
        if int(options.get("enable", 0)) != 1:
            findings.append(
                Finding(
                    category="Proxmox",
                    target="Datacenter",
                    title="Datacenter Firewall Disabled",
                    description=(
                        "The cluster-wide Proxmox Datacenter firewall is disabled, "
                        "preventing centralized firewall rules from being enforced."
                    ),
                    severity=Severity.MEDIUM,
                    remediation=(
                        "Enable the Datacenter firewall under Datacenter -> Firewall -> "
                        "Options and define default drop/allow policies."
                    ),
                    fix_id="proxmox.cluster_firewall",
                    fix_description="Enable Proxmox Datacenter firewall via API",
                )
            )
    except Exception as exc:
        console.print(f"[yellow]Warning: Could not inspect Datacenter firewall: {exc}[/yellow]")
    return findings


def _audit_api_tokens(proxmox: Any, console: Console) -> list[Finding]:
    """Check for Proxmox API tokens configured without privilege separation."""
    findings: list[Finding] = []
    try:
        users = proxmox.access.users.get()
    except Exception as exc:
        console.print(f"[yellow]Warning: Could not list Proxmox users for token audit: {exc}[/yellow]")
        return findings

    for user in users:
        userid = user.get("userid")
        if not userid:
            continue
        try:
            tokens = proxmox.access.users(userid).token.get()
        except Exception:
            continue

        for token in tokens:
            tokenid = token.get("tokenid", "<unknown>")
            if int(token.get("privsep", 1)) == 0:
                findings.append(
                    Finding(
                        category="Proxmox",
                        target=f"{userid}!{tokenid}",
                        title="API Token Without Privilege Separation (privsep=0)",
                        description=(
                            f"API token '{userid}!{tokenid}' has privilege separation disabled "
                            "(privsep=0), granting it all permissions of the parent user."
                        ),
                        severity=Severity.MEDIUM,
                        remediation=(
                            "Recreate or update the API token with Privilege Separation enabled "
                            "(privsep=1) and assign only least-privilege ACLs."
                        ),
                    )
                )

    return findings


def _audit_node_firewall(proxmox: Any, node_name: str, console: Console) -> list[Finding]:
    """Check whether a Proxmox node's host firewall is enabled."""
    findings: list[Finding] = []
    try:
        options = proxmox.nodes(node_name).firewall.options.get()
        if int(options.get("enable", 0)) != 1:
            findings.append(
                Finding(
                    category="Proxmox",
                    target=f"node/{node_name}",
                    title="Proxmox Node Firewall Disabled",
                    description=(
                        f"Host-level firewall is disabled on Proxmox node '{node_name}', "
                        "leaving management interfaces and node services unfiltered."
                    ),
                    severity=Severity.MEDIUM,
                    remediation=(
                        f"Enable the firewall under Node '{node_name}' -> Firewall -> Options "
                        "and allowlist management ports (8006, 22) from trusted IPs only."
                    ),
                    fix_id="proxmox.node_firewall",
                    fix_description=f"Enable Proxmox Node '{node_name}' firewall via API",
                )
            )
    except Exception as exc:
        console.print(f"[yellow]Warning: Could not inspect firewall on node '{node_name}': {exc}[/yellow]")
    return findings


def _audit_lxc_containers(proxmox: Any, node_name: str, console: Console) -> list[Finding]:
    """Audit LXC containers on a Proxmox node."""
    findings: list[Finding] = []
    try:
        containers = proxmox.nodes(node_name).lxc.get()
    except Exception as exc:
        console.print(f"[yellow]Warning: Could not list LXC containers on '{node_name}': {exc}[/yellow]")
        return findings

    for ct in containers:
        vmid = ct.get("vmid")
        name = ct.get("name") or f"CT-{vmid}"
        target = f"lxc/{vmid} ({name})"

        try:
            cfg = proxmox.nodes(node_name).lxc(vmid).config.get()
        except Exception as exc:
            console.print(f"[yellow]Warning: Could not read config for {target}: {exc}[/yellow]")
            continue

        is_unprivileged = int(cfg.get("unprivileged", 0)) == 1
        if not is_unprivileged:
            findings.append(
                Finding(
                    category="Proxmox",
                    target=target,
                    title="Privileged LXC Container",
                    description=(
                        f"LXC container {target} on node '{node_name}' is running as a "
                        "privileged container (unprivileged=0 or unset), sharing UID 0 "
                        "mapping with the Proxmox host."
                    ),
                    severity=Severity.HIGH,
                    remediation=(
                        f"Manual remediation required (auto-conversion disabled to preserve file ownership): "
                        f"1) vzdump {vmid} --mode stop --compress zstd; "
                        f"2) pct restore {vmid} /var/lib/vz/dump/vzdump-lxc-{vmid}-*.tar.zst --unprivileged 1 --force."
                    ),
                )
            )

            features = str(cfg.get("features") or "").lower()
            matched_features = [feat for feat in _RISKY_LXC_FEATURES if feat in features]
            if matched_features:
                findings.append(
                    Finding(
                        category="Proxmox",
                        target=target,
                        title="Risky Features Enabled on Privileged LXC Container",
                        description=(
                            f"Privileged LXC container {target} has risky features enabled: "
                            f"{', '.join(matched_features)}. Combined with privileged mode, "
                            "this significantly increases container escape risk."
                        ),
                        severity=Severity.HIGH,
                        remediation=(
                            "Convert the container to unprivileged or disable unnecessary "
                            "features (nesting, keyctl, fuse) in the LXC configuration."
                        ),
                    )
                )

        for iface, iface_val in _parse_net_interfaces(cfg).items():
            if not _has_firewall_enabled(iface_val):
                findings.append(
                    Finding(
                        category="Proxmox",
                        target=f"{target} [{iface}]",
                        title="LXC Network Interface Firewall Disabled",
                        description=(
                            f"Interface '{iface}' on LXC container {target} does not have "
                            "'firewall=1' enabled."
                        ),
                        severity=Severity.MEDIUM,
                        remediation=(
                            f"Enable the Firewall checkbox on {iface} in Proxmox UI or add "
                            "'firewall=1' to the interface configuration."
                        ),
                        fix_id="proxmox.guest_firewall",
                        fix_description=f"Enable firewall=1 on {target} interface {iface} via Proxmox API",
                    )
                )

    return findings


def _audit_qemu_vms(proxmox: Any, node_name: str, console: Console) -> list[Finding]:
    """Audit QEMU virtual machines on a Proxmox node."""
    findings: list[Finding] = []
    try:
        vms = proxmox.nodes(node_name).qemu.get()
    except Exception as exc:
        console.print(f"[yellow]Warning: Could not list QEMU VMs on '{node_name}': {exc}[/yellow]")
        return findings

    for vm in vms:
        vmid = vm.get("vmid")
        name = vm.get("name") or f"VM-{vmid}"
        target = f"qemu/{vmid} ({name})"

        try:
            cfg = proxmox.nodes(node_name).qemu(vmid).config.get()
        except Exception as exc:
            console.print(f"[yellow]Warning: Could not read config for {target}: {exc}[/yellow]")
            continue

        for iface, iface_val in _parse_net_interfaces(cfg).items():
            if not _has_firewall_enabled(iface_val):
                findings.append(
                    Finding(
                        category="Proxmox",
                        target=f"{target} [{iface}]",
                        title="QEMU VM Network Interface Firewall Disabled",
                        description=(
                            f"Interface '{iface}' on VM {target} does not have "
                            "'firewall=1' enabled."
                        ),
                        severity=Severity.MEDIUM,
                        remediation=(
                            f"Enable the Firewall option on {iface} in Proxmox UI or set "
                            "'firewall=1' in the VM hardware network configuration."
                        ),
                        fix_id="proxmox.guest_firewall",
                        fix_description=f"Enable firewall=1 on {target} interface {iface} via Proxmox API",
                    )
                )

    return findings


def _redact_secret(text: str, secret: str) -> str:
    """Mask an API token secret if it appears in an exception or log string."""
    if not secret:
        return text
    return text.replace(secret, "***REDACTED***")


def run_proxmox_audit(
    config: dict[str, Any],
    console: Console | None = None,
) -> list[Finding]:
    """Audit a Proxmox VE cluster, nodes, VMs, LXC containers, and API tokens.

    Args:
        config: The ``proxmox`` section from the AegisInfra configuration.
        console: Optional Rich console for status/warning output.

    Returns:
        A list of discovered Proxmox security findings.
    """
    out = console or Console()
    if not config.get("enabled", False):
        return []

    try:
        from proxmoxer import ProxmoxAPI
    except ImportError:
        out.print("[yellow]Warning: 'proxmoxer' package is not installed; skipping Proxmox audit.[/yellow]")
        return []

    host = str(config.get("host") or "").strip()
    user = str(config.get("user") or "").strip()
    token_name = str(config.get("token_name") or "").strip()
    token_value = str(config.get("token_value") or "").strip()
    port = int(config.get("port", 8006))
    verify_ssl = bool(config.get("verify_ssl", False))

    if not all([host, user, token_name, token_value]):
        out.print("[yellow]Warning: Proxmox credentials incomplete; skipping Proxmox audit.[/yellow]")
        return []

    if not verify_ssl:
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    try:
        proxmox = ProxmoxAPI(
            host,
            port=port,
            user=user,
            token_name=token_name,
            token_value=token_value,
            verify_ssl=verify_ssl,
            timeout=10,
        )
        nodes = proxmox.nodes.get()
    except Exception as exc:
        safe_err = _redact_secret(str(exc), token_value)
        out.print(f"[yellow]Warning: Unable to connect to Proxmox VE at {host}:{port} ({safe_err}); skipping Proxmox audit.[/yellow]")
        return []

    findings: list[Finding] = []
    findings.extend(_audit_cluster_firewall(proxmox, out))
    findings.extend(_audit_api_tokens(proxmox, out))

    for node in nodes:
        node_name = node.get("node")
        if not node_name:
            continue
        findings.extend(_audit_node_firewall(proxmox, node_name, out))
        findings.extend(_audit_lxc_containers(proxmox, node_name, out))
        findings.extend(_audit_qemu_vms(proxmox, node_name, out))

    return findings
