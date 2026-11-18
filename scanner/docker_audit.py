"""Docker daemon, container, and image security auditor."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from rich.console import Console

from models import Finding, Severity

_SENSITIVE_MOUNT_PREFIXES = ("/var/run/docker.sock", "/etc", "/root")


def _is_sensitive_mount(source: str) -> bool:
    """Return True if a host mount path exposes a sensitive host directory or socket."""
    normalized = source.rstrip("/") or "/"
    if normalized == "/":
        return True
    return any(
        normalized == prefix or normalized.startswith(f"{prefix}/")
        for prefix in _SENSITIVE_MOUNT_PREFIXES
    )


def _extract_mount_sources(attrs: dict[str, Any]) -> list[str]:
    """Collect host source paths from container Mounts and HostConfig.Binds."""
    sources: list[str] = []
    seen: set[str] = set()

    for mount in attrs.get("Mounts") or []:
        if mount.get("Type") == "bind":
            src = str(mount.get("Source") or "").strip()
            if src and src not in seen:
                seen.add(src)
                sources.append(src)

    for bind in (attrs.get("HostConfig") or {}).get("Binds") or []:
        src = str(bind).split(":", 1)[0].strip()
        if src.startswith("/") and src not in seen:
            seen.add(src)
            sources.append(src)

    return sources


def _audit_container(container: Any) -> list[Finding]:
    """Audit a single Docker container's runtime security configuration."""
    findings: list[Finding] = []
    attrs: dict[str, Any] = container.attrs or {}
    name = str(container.name or container.short_id)
    host_cfg: dict[str, Any] = attrs.get("HostConfig") or {}
    cfg: dict[str, Any] = attrs.get("Config") or {}
    net_settings: dict[str, Any] = attrs.get("NetworkSettings") or {}

    # 1. Privileged mode -> CRITICAL
    if host_cfg.get("Privileged") is True:
        findings.append(
            Finding(
                category="Docker",
                target=name,
                title="Container Running in Privileged Mode",
                description=(
                    f"Container '{name}' is running with --privileged=true, granting "
                    "nearly full kernel capabilities and host device access."
                ),
                severity=Severity.CRITICAL,
                remediation=(
                    "Remove --privileged and grant only the minimal Linux capabilities "
                    "needed via --cap-drop=ALL and --cap-add=<CAP>."
                ),
            )
        )

    # 2. Sensitive host mounts -> HIGH
    for src in _extract_mount_sources(attrs):
        if _is_sensitive_mount(src):
            findings.append(
                Finding(
                    category="Docker",
                    target=name,
                    title=f"Sensitive Host Path Mounted ({src})",
                    description=(
                        f"Container '{name}' bind-mounts sensitive host path '{src}', "
                        "which can enable host escape or credential theft."
                    ),
                    severity=Severity.HIGH,
                    remediation=(
                        f"Remove the bind mount for '{src}' or use a least-privilege "
                        "Docker socket proxy / read-only scoped volume."
                    ),
                )
            )

    # 3. Ports bound to 0.0.0.0 (or ::) instead of 127.0.0.1 -> MEDIUM
    ports_map = net_settings.get("Ports") or host_cfg.get("PortBindings") or {}
    wildcard_bindings: list[str] = []
    for container_port, bindings in ports_map.items():
        if not bindings:
            continue
        for binding in bindings:
            host_ip = str(binding.get("HostIp") or "").strip()
            host_port = str(binding.get("HostPort") or "").strip()
            if host_ip in ("", "0.0.0.0", "::"):
                display_ip = host_ip or "0.0.0.0"
                wildcard_bindings.append(f"{display_ip}:{host_port}->{container_port}")

    if wildcard_bindings:
        findings.append(
            Finding(
                category="Docker",
                target=name,
                title="Container Ports Bound to All Interfaces (0.0.0.0)",
                description=(
                    f"Container '{name}' exposes ports on all network interfaces: "
                    f"{', '.join(wildcard_bindings)}. This bypasses some host firewall rules."
                ),
                severity=Severity.MEDIUM,
                remediation=(
                    "Bind published ports explicitly to 127.0.0.1 (e.g., 127.0.0.1:8080:80) "
                    "and front services with a TLS reverse proxy or VPN."
                ),
            )
        )

    # 4. host network or pid namespace sharing -> MEDIUM
    for mode_key, label in (("NetworkMode", "network_mode: host"), ("PidMode", "pid_mode: host")):
        if host_cfg.get(mode_key) == "host":
            findings.append(
                Finding(
                    category="Docker",
                    target=name,
                    title=f"Container Shares Host Namespace ({label})",
                    description=(
                        f"Container '{name}' is configured with {label}, weakening "
                        "container isolation from the host."
                    ),
                    severity=Severity.MEDIUM,
                    remediation=(
                        f"Avoid {label}; use isolated bridge networks and default PID "
                        "namespaces unless strictly required."
                    ),
                )
            )

    # 5. Running as root -> LOW
    user = str(cfg.get("User") or "").strip()
    user_part = user.split(":", 1)[0].strip()
    if user_part in ("", "0", "root"):
        findings.append(
            Finding(
                category="Docker",
                target=name,
                title="Container Configured to Run as Root",
                description=(
                    f"Container '{name}' has User set to '{user or '<unset>'}', so "
                    "processes run as UID 0 inside the container."
                ),
                severity=Severity.LOW,
                remediation=(
                    "Set a non-root USER in the Dockerfile or specify 'user: 1000:1000' "
                    "in docker-compose.yml."
                ),
            )
        )

    return findings


def _parse_docker_timestamp(ts: str) -> datetime | None:
    """Parse an ISO-8601 Docker timestamp (with optional nanoseconds) into UTC datetime."""
    if not ts:
        return None
    cleaned = ts.strip()
    if cleaned.endswith("Z"):
        cleaned = f"{cleaned[:-1]}+00:00"
    # Truncate fractional seconds to 6 digits for Python fromisoformat compatibility
    if "." in cleaned:
        head, tail = cleaned.split(".", 1)
        tz_idx = max(tail.find("+"), tail.find("-"))
        if tz_idx != -1:
            frac = tail[:tz_idx][:6]
            tz = tail[tz_idx:]
            cleaned = f"{head}.{frac}{tz}"
        else:
            cleaned = f"{head}.{tail[:6]}"
    try:
        dt = datetime.fromisoformat(cleaned)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _audit_images(client: Any, max_image_age_days: int) -> list[Finding]:
    """Audit local Docker images for staleness and mutable :latest tags."""
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)

    for image in client.images.list():
        tags: list[str] = image.tags or []
        target = tags[0] if tags else str(image.short_id)

        # Check mutable :latest or untagged images -> INFO
        if not tags or any(tag.endswith(":latest") or ":" not in tag.rsplit("/", 1)[-1] for tag in tags):
            findings.append(
                Finding(
                    category="Docker",
                    target=target,
                    title="Mutable ':latest' or Untagged Image Used",
                    description=(
                        f"Image '{target}' relies on a mutable ':latest' or missing tag, "
                        "reducing build reproducibility and complicating rollbacks."
                    ),
                    severity=Severity.INFO,
                    remediation="Pin container images to immutable semantic version tags or SHA256 digests.",
                )
            )

        # Check image age -> LOW
        created_raw = str((image.attrs or {}).get("Created") or "")
        created_dt = _parse_docker_timestamp(created_raw)
        if created_dt is not None:
            age_days = (now - created_dt).days
            if age_days > max_image_age_days:
                findings.append(
                    Finding(
                        category="Docker",
                        target=target,
                        title=f"Outdated Docker Image ({age_days} Days Old)",
                        description=(
                            f"Image '{target}' was built {age_days} days ago, exceeding "
                            f"the configured {max_image_age_days}-day threshold and likely "
                            "missing upstream security patches."
                        ),
                        severity=Severity.LOW,
                        remediation="Rebuild or pull a newer base image and redeploy dependent containers.",
                    )
                )

    return findings


def run_docker_audit(
    config: dict[str, Any],
    console: Console | None = None,
) -> list[Finding]:
    """Audit Docker containers and images for security misconfigurations.

    Args:
        config: The ``docker`` section from the AegisInfra configuration.
        console: Optional Rich console for status/warning output.

    Returns:
        A list of discovered Docker security findings.
    """
    out = console or Console()
    if not config.get("enabled", True):
        return []

    try:
        import docker
        from docker.errors import DockerException
    except ImportError:
        out.print("[yellow]Warning: 'docker' package is not installed; skipping Docker audit.[/yellow]")
        return []

    socket_url = str(config.get("socket_url") or "").strip()
    include_stopped = bool(config.get("include_stopped", False))
    max_image_age_days = int(config.get("max_image_age_days", 90))

    client = None
    try:
        client = docker.DockerClient(base_url=socket_url) if socket_url else docker.from_env()
        client.ping()
    except DockerException as exc:
        out.print(f"[yellow]Warning: Unable to connect to Docker daemon ({exc}); skipping Docker audit.[/yellow]")
        return []
    except Exception as exc:
        out.print(f"[yellow]Warning: Docker initialization failed ({exc}); skipping Docker audit.[/yellow]")
        return []

    findings: list[Finding] = []
    try:
        containers = client.containers.list(all=include_stopped)
        for container in containers:
            try:
                findings.extend(_audit_container(container))
            except Exception as exc:
                out.print(f"[yellow]Warning: Failed to inspect container {container.short_id}: {exc}[/yellow]")

        try:
            findings.extend(_audit_images(client, max_image_age_days))
        except Exception as exc:
            out.print(f"[yellow]Warning: Failed to audit Docker images: {exc}[/yellow]")
    except Exception as exc:
        out.print(f"[yellow]Warning: Docker audit error: {exc}[/yellow]")
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass

    return findings
