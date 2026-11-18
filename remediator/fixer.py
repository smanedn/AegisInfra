"""Safe, reversible auto-remediation engine with explicit user confirmation."""

from __future__ import annotations

import os
import re
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer
import yaml
from rich.console import Console
from rich.table import Table

from models import AuditReport, Finding, RemediationLog

_GUEST_TARGET_RE = re.compile(r"^(lxc|qemu)/(\d+)\s+.*\[([^\]]+)\]$")


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def get_fixable_findings(report: AuditReport) -> list[Finding]:
    """Return all findings in the report that support safe automated remediation."""
    return [f for f in report.sorted_findings() if f.fix_id is not None]


def count_fixable_findings(report: AuditReport) -> int:
    """Return the number of findings in the report that have a safe fix_id."""
    return len(get_fixable_findings(report))


def _record(
    report: AuditReport,
    target: str,
    action: str,
    status: str,
    console: Console,
) -> RemediationLog:
    entry = RemediationLog(
        timestamp=_now_utc(),
        target=target,
        action=action,
        status=status,
    )
    report.remediations.append(entry)
    color = {
        "APPLIED": "green",
        "DRY_RUN": "cyan",
        "SKIPPED": "yellow",
        "FAILED": "red",
        "MANUAL": "magenta",
    }.get(status, "white")
    console.print(f"  [{color}][{status}][/{color}] {target}: {action}")
    return entry


def _has_permissive_config(config_path: Path) -> bool:
    """Return True if config_path exists and has overly permissive POSIX permissions."""
    if not config_path.exists():
        return False
    if os.name == "nt":
        return False
    try:
        mode = stat.S_IMODE(config_path.stat().st_mode)
    except OSError:
        return False
    return mode not in (0o600, 0o640, 0o400, 0o440)


def _confirm_or_auto(prompt_text: str, auto_approve: bool) -> bool:
    """Return True immediately if auto_approve is set, otherwise prompt via typer.confirm."""
    if auto_approve:
        return True
    return typer.confirm(prompt_text, default=False)


def _fix_config_permissions(
    report: AuditReport,
    config_path: Path,
    dry_run: bool,
    auto_approve: bool,
    console: Console,
) -> None:
    """Restrict config.yaml permissions on POSIX or Windows."""
    if not config_path.exists():
        return

    if os.name == "nt":
        user = os.environ.get("USERNAME") or os.getlogin()
        cmd = ["icacls", str(config_path), "/inheritance:r", "/grant:r", f"{user}:F"]
        action_desc = f"Restrict Windows ACL on '{config_path}' to user '{user}' only"
        if dry_run:
            _record(report, str(config_path), f"[DRY-RUN] {' '.join(cmd)}", "DRY_RUN", console)
            return
        if not _confirm_or_auto(f"Apply fix: {action_desc}?", auto_approve):
            _record(report, str(config_path), action_desc, "SKIPPED", console)
            return
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            _record(report, str(config_path), action_desc, "APPLIED", console)
        except Exception as exc:
            _record(report, str(config_path), f"{action_desc} ({exc})", "FAILED", console)
        return

    if not _has_permissive_config(config_path):
        return

    action_desc = f"Restrict permissions on '{config_path}' to 0600 (chmod 600)"
    if dry_run:
        _record(report, str(config_path), f"[DRY-RUN] chmod 600 {config_path}", "DRY_RUN", console)
        return
    if not _confirm_or_auto(f"Apply fix: {action_desc}?", auto_approve):
        _record(report, str(config_path), action_desc, "SKIPPED", console)
        return
    try:
        os.chmod(config_path, 0o600)
        _record(report, str(config_path), action_desc, "APPLIED", console)
    except Exception as exc:
        _record(report, str(config_path), f"{action_desc} ({exc})", "FAILED", console)


def _apply_docker_compose_overrides(
    report: AuditReport,
    docker_findings: list[Finding],
    output_dir: Path,
    dry_run: bool,
    auto_approve: bool,
    console: Console,
) -> None:
    """Generate a non-destructive docker-compose.override.yml for container hardening."""
    compose_fix_ids = {"docker.privileged", "docker.sensitive_mount", "docker.wildcard_port"}
    relevant = [f for f in docker_findings if f.fix_id in compose_fix_ids]
    if not relevant:
        return

    override_path = output_dir / "docker-compose.override.yml"
    services: dict[str, dict[str, Any]] = {}
    for finding in relevant:
        svc = services.setdefault(finding.target, {})
        if finding.fix_id == "docker.privileged":
            svc["privileged"] = False
            svc.setdefault("cap_drop", ["ALL"])
        elif finding.fix_id == "docker.wildcard_port":
            svc.setdefault("ports", ["127.0.0.1:8080:8080  # Replace with exact container port mapping"])
        elif finding.fix_id == "docker.sensitive_mount":
            svc.setdefault("security_opt", ["no-new-privileges:true"])

    payload = {"services": services}
    action_desc = f"Generate hardened Compose override at '{override_path}'"

    if dry_run:
        _record(
            report,
            "Docker Compose",
            f"[DRY-RUN] Write {override_path} for services: {', '.join(services)}",
            "DRY_RUN",
            console,
        )
        return

    if not _confirm_or_auto(
        f"Apply fix: {action_desc} for {len(services)} service(s) (non-destructive)?",
        auto_approve,
    ):
        _record(report, "Docker Compose", action_desc, "SKIPPED", console)
        return

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        header = (
            "# Generated by AegisInfra Auto-Remediation\n"
            "# Review port mappings and volume mounts, then apply with: docker compose up -d\n"
        )
        override_path.write_text(header + yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        _record(report, "Docker Compose", action_desc, "APPLIED", console)
    except Exception as exc:
        _record(report, "Docker Compose", f"{action_desc} ({exc})", "FAILED", console)


def _prune_docker_images(
    report: AuditReport,
    docker_cfg: dict[str, Any],
    dry_run: bool,
    auto_approve: bool,
    console: Console,
) -> None:
    """Safely prune unused/dangling Docker images after confirmation."""
    action_desc = "Prune unused/dangling Docker images (docker image prune)"
    if dry_run:
        _record(report, "Docker Images", f"[DRY-RUN] {action_desc}", "DRY_RUN", console)
        return

    if not _confirm_or_auto(f"Apply fix: {action_desc}?", auto_approve):
        _record(report, "Docker Images", action_desc, "SKIPPED", console)
        return

    try:
        import docker

        socket_url = str(docker_cfg.get("socket_url") or "").strip()
        client = docker.DockerClient(base_url=socket_url) if socket_url else docker.from_env()
        try:
            res = client.images.prune(filters={"dangling": True})
            reclaimed = int((res or {}).get("SpaceReclaimed") or 0)
            _record(
                report,
                "Docker Images",
                f"Pruned dangling images (reclaimed {reclaimed} bytes)",
                "APPLIED",
                console,
            )
        finally:
            client.close()
    except Exception as exc:
        _record(report, "Docker Images", f"{action_desc} ({exc})", "FAILED", console)


def _connect_proxmox(proxmox_cfg: dict[str, Any]) -> Any:
    """Create a ProxmoxAPI client from configuration."""
    from proxmoxer import ProxmoxAPI

    host = str(proxmox_cfg.get("host") or "").strip()
    user = str(proxmox_cfg.get("user") or "").strip()
    token_name = str(proxmox_cfg.get("token_name") or "").strip()
    token_value = str(proxmox_cfg.get("token_value") or "").strip()
    port = int(proxmox_cfg.get("port", 8006))
    verify_ssl = bool(proxmox_cfg.get("verify_ssl", False))

    return ProxmoxAPI(
        host,
        port=port,
        user=user,
        token_name=token_name,
        token_value=token_value,
        verify_ssl=verify_ssl,
        timeout=10,
    )


def _find_guest_node(proxmox: Any, guest_type: str, vmid: str) -> str | None:
    """Locate the Proxmox node hosting a given LXC or QEMU VMID."""
    for node in proxmox.nodes.get():
        node_name = node.get("node")
        if not node_name:
            continue
        guests = getattr(proxmox.nodes(node_name), guest_type).get()
        if any(str(g.get("vmid")) == vmid for g in guests):
            return str(node_name)
    return None


def _apply_proxmox_remediations(
    report: AuditReport,
    proxmox_findings: list[Finding],
    proxmox_cfg: dict[str, Any],
    dry_run: bool,
    auto_approve: bool,
    console: Console,
) -> None:
    """Enable Proxmox Datacenter, Node, and VM/LXC interface firewalls via API."""
    fixable = [f for f in proxmox_findings if f.fix_id is not None]
    if not fixable:
        return

    proxmox = None

    def _get_proxmox() -> Any:
        nonlocal proxmox
        if proxmox is None:
            proxmox = _connect_proxmox(proxmox_cfg)
        return proxmox

    for finding in fixable:
        if finding.fix_id == "proxmox.cluster_firewall":
            action_desc = "Enable Proxmox Datacenter firewall (enable=1)"
            if dry_run:
                _record(report, finding.target, "[DRY-RUN] PUT /cluster/firewall/options enable=1", "DRY_RUN", console)
                continue
            if not _confirm_or_auto(f"Apply fix on {finding.target}: {action_desc}?", auto_approve):
                _record(report, finding.target, action_desc, "SKIPPED", console)
                continue
            try:
                _get_proxmox().cluster.firewall.options.put(enable=1)
                _record(report, finding.target, action_desc, "APPLIED", console)
            except Exception as exc:
                _record(report, finding.target, f"{action_desc} ({exc})", "FAILED", console)

        elif finding.fix_id == "proxmox.node_firewall":
            node_name = finding.target.removeprefix("node/")
            action_desc = f"Enable firewall on Proxmox node '{node_name}' (enable=1)"
            if dry_run:
                _record(
                    report,
                    finding.target,
                    f"[DRY-RUN] PUT /nodes/{node_name}/firewall/options enable=1",
                    "DRY_RUN",
                    console,
                )
                continue
            if not _confirm_or_auto(f"Apply fix on {finding.target}: {action_desc}?", auto_approve):
                _record(report, finding.target, action_desc, "SKIPPED", console)
                continue
            try:
                _get_proxmox().nodes(node_name).firewall.options.put(enable=1)
                _record(report, finding.target, action_desc, "APPLIED", console)
            except Exception as exc:
                _record(report, finding.target, f"{action_desc} ({exc})", "FAILED", console)

        elif finding.fix_id == "proxmox.guest_firewall":
            match = _GUEST_TARGET_RE.match(finding.target)
            if not match:
                _record(report, finding.target, "Could not parse guest target", "FAILED", console)
                continue
            guest_type, vmid, iface = match.groups()
            action_desc = f"Enable firewall=1 on {guest_type}/{vmid} interface {iface}"
            if dry_run:
                _record(
                    report,
                    finding.target,
                    f"[DRY-RUN] PUT /nodes/<node>/{guest_type}/{vmid}/config {iface}=...,firewall=1",
                    "DRY_RUN",
                    console,
                )
                continue
            if not _confirm_or_auto(f"Apply fix on {finding.target}: {action_desc}?", auto_approve):
                _record(report, finding.target, action_desc, "SKIPPED", console)
                continue
            try:
                px = _get_proxmox()
                node_name = _find_guest_node(px, guest_type, vmid)
                if not node_name:
                    _record(report, finding.target, "Guest node not found", "FAILED", console)
                    continue
                guest_api = getattr(px.nodes(node_name), guest_type)(vmid)
                cfg = guest_api.config.get()
                current_val = str(cfg.get(iface) or "")
                updated_val = f"{current_val},firewall=1" if current_val else "firewall=1"
                guest_api.config.put(**{iface: updated_val})
                _record(report, finding.target, action_desc, "APPLIED", console)
            except Exception as exc:
                _record(report, finding.target, f"{action_desc} ({exc})", "FAILED", console)


def _render_remediation_table(remediations: list[RemediationLog], console: Console) -> None:
    if not remediations:
        return
    table = Table(title="Remediation Summary", show_lines=True, header_style="bold cyan")
    table.add_column("Timestamp", width=22)
    table.add_column("Target", max_width=28)
    table.add_column("Action", max_width=52)
    table.add_column("Status", width=10, justify="center")

    for item in remediations:
        table.add_row(item.timestamp, item.target, item.action, item.status)

    console.print()
    console.print(table)


def run_remediation(
    report: AuditReport,
    config: dict[str, Any],
    config_path: Path | None = None,
    output_dir: Path | None = None,
    dry_run: bool = False,
    selected_findings: list[Finding] | None = None,
    auto_approve: bool = False,
    console: Console | None = None,
) -> list[RemediationLog]:
    """Interactively review and apply safe remediations for detected findings.

    Args:
        report: Populated AuditReport containing scan findings.
        config: Full parsed AegisInfra configuration dictionary.
        config_path: Optional path to ``config.yaml`` for permission hardening.
        output_dir: Directory where generated Compose override files are saved.
        dry_run: If True, preview exact commands/API calls without modifying state.
        selected_findings: Optional subset of findings to remediate (defaults to all).
        auto_approve: If True, skip per-item typer.confirm prompts (after menu choice).
        console: Optional Rich console for status output.

    Returns:
        List of RemediationLog entries recorded during this session.
    """
    out = console or Console()
    mode_label = "DRY-RUN PREVIEW" if dry_run else "INTERACTIVE REMEDIATION"
    out.print(f"\n[bold cyan]Starting {mode_label}...[/bold cyan]")

    if config_path is not None and selected_findings is None:
        _fix_config_permissions(
            report,
            config_path,
            dry_run=dry_run,
            auto_approve=auto_approve,
            console=out,
        )

    active_findings = selected_findings if selected_findings is not None else report.findings
    docker_findings = [f for f in active_findings if f.category == "Docker"]
    target_dir = output_dir or Path(str((config.get("general") or {}).get("output_dir") or "./reports"))
    _apply_docker_compose_overrides(
        report,
        docker_findings,
        target_dir,
        dry_run=dry_run,
        auto_approve=auto_approve,
        console=out,
    )

    if any(f.fix_id == "docker.prune_images" for f in docker_findings):
        _prune_docker_images(
            report,
            config.get("docker") or {},
            dry_run=dry_run,
            auto_approve=auto_approve,
            console=out,
        )

    proxmox_findings = [f for f in active_findings if f.category == "Proxmox"]
    _apply_proxmox_remediations(
        report,
        proxmox_findings,
        config.get("proxmox") or {},
        dry_run=dry_run,
        auto_approve=auto_approve,
        console=out,
    )

    _render_remediation_table(report.remediations, out)
    return report.remediations
