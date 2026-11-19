# Changelog

All notable changes to **AegisInfra** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-19

### Added
- **Network & Port Scanner (`scanner/network.py`)**: Concurrent TCP port scanning across IPs/CIDR ranges with non-intrusive socket banner grabbing and risk-based severity classification (`CRITICAL`–`INFO`).
- **Docker Security Auditor (`scanner/docker_audit.py`)**: Audits privileged containers, sensitive host bind mounts (`/var/run/docker.sock`, `/`, `/etc`, `/root`), `0.0.0.0` port bindings, `host` network/PID namespaces, `root` user execution, outdated images, and `:latest` tags.
- **Proxmox VE Auditor (`scanner/proxmox_audit.py`)**: API-token authenticated auditing for Datacenter/Node/VM/LXC firewalls, privileged LXC containers (`unprivileged=0`), risky LXC features (`nesting=1`, `keyctl=1`), and API tokens without privilege separation (`privsep=0`).
- **Interactive HTML & Optional PDF Reporting (`reporter/`)**:
  - Self-contained offline HTML dashboard with embedded SVG emblem, before/after Security Score (`0–100`), KPI cards, severity/category/keyword filtering, and copyable remediation snippets.
  - Optional PDF export via WeasyPrint with graceful fallback to HTML-only when system GTK/Pango libraries are unavailable.
- **Interactive & CLI Auto-Remediation (`remediator/fixer.py`)**:
  - Post-report interactive menu (`[A]` Fix all, `[S]` Select specific, `[N]` Skip) plus `--fix` and `--dry-run` flags.
  - Safe, reversible handlers for `config.yaml` permissions (`chmod 600` / `icacls`), non-destructive `docker-compose.override.yml` generation, dangling image pruning, and Proxmox firewall enablement via API.
  - Automatic HTML/PDF report regeneration after applying fixes.
- **Unified Launcher & Windows One-Click Execution (`start.py`, `AegisInfra.bat`)**:
  - Automatic `config.yaml` initialization, environment/security self-checks, `pytest` execution, live scan, and automatic browser opening.
- **Verification & Test Suite (`healthcheck.py`, `tests/`)**:
  - Standalone `healthcheck.py` runner with mocked E2E XSS escaping verification and `pytest` unit tests across all core modules.
- **Packaging & CLI Versioning**: Added `LICENSE` (MIT), `pyproject.toml`, `__version__ = "1.0.0"`, and `--version` / `-V` flags on `main.py` and `start.py`.
