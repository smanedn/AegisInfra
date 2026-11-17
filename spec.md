# Project Specification: AegisInfra

Create a complete, production-ready Python CLI security auditing tool named **AegisInfra** for self-hosted infrastructures, homelabs, and small server environments.

Generate the entire project directory structure, source code, configuration templates, HTML report template, `.gitignore`, and `README.md` from scratch.

## 1. Directory Structure
Create the following files and folders:
- `main.py`
- `models.py`
- `config.example.yaml`
- `requirements.txt`
- `.gitignore`
- `README.md`
- `scanner/__init__.py`
- `scanner/network.py`
- `scanner/docker_audit.py`
- `scanner/proxmox_audit.py`
- `reporter/__init__.py`
- `reporter/generator.py`
- `reporter/template.html`

## 2. Tech Stack & Dependencies (`requirements.txt`)
- Python 3.11+
- `typer>=0.12.0` & `rich>=13.7.0` (CLI interface, progress spinners, color-coded terminal tables)
- `pyyaml>=6.0.1` (YAML config parsing)
- `docker>=7.0.0` (Official Docker SDK)
- `proxmoxer>=2.0.1` & `requests>=2.31.0` (Proxmox VE API client)
- `jinja2>=3.1.3` (Standalone HTML report rendering)
- `weasyprint>=61.0` (Optional HTML-to-PDF export; handle missing system GTK/Pango dependencies gracefully without crashing)

## 3. Core Data Models (`models.py`)
Define clean dataclasses and enums:
- `Severity(str, Enum)`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- `Finding`:
  - `category: str` (`"Network"`, `"Docker"`, `"Proxmox"`)
  - `target: str` (e.g., container name, VMID, `IP:Port`)
  - `title: str`
  - `description: str`
  - `severity: Severity`
  - `remediation: str`
- `AuditReport`:
  - `timestamp: str`
  - `hostname: str`
  - `findings: list[Finding]`
  - Helper methods: `add_finding(finding)` and `summary() -> dict[str, int]` returning counts per severity.

## 4. Module Specifications

### A. Network & Port Scanner (`scanner/network.py`)
- Scan configured target IPs/CIDR subnets and TCP port lists concurrently using `concurrent.futures.ThreadPoolExecutor`.
- Perform non-intrusive socket banner grabbing on open ports to fingerprint exposed services.
- Flag findings based on exposure risk:
  - Unencrypted/insecure services (e.g., Telnet port 23, FTP port 21, unauthenticated Docker daemon port 2375, exposed Redis 6379) -> `CRITICAL` or `HIGH`.
  - Plain HTTP (80, 8080) or exposed databases (3306, 5432) -> `MEDIUM`.
  - Informational open ports (e.g., SSH 22, HTTPS 443) -> `INFO`.

### B. Docker Security Auditor (`scanner/docker_audit.py`)
- Connect to the Docker daemon via `socket_url` from config.
- Inspect all running (and optionally stopped) containers and images:
  - Container running in `--privileged` mode -> `CRITICAL`.
  - Sensitive host mounts (`/var/run/docker.sock`, `/`, `/etc`, `/root`) -> `HIGH`.
  - Ports bound to `0.0.0.0` instead of `127.0.0.1` -> `MEDIUM`.
  - Container using `network_mode: host` or `pid_mode: host` -> `MEDIUM`.
  - Running as `root` user (`User` unset or `"0"` / `"root"`) -> `LOW`.
  - Outdated images (built older than `max_image_age_days`) or mutable `:latest` tags -> `LOW` / `INFO`.

### C. Proxmox VE Auditor (`scanner/proxmox_audit.py`)
- Connect to Proxmox VE API using `proxmoxer` with API Token authentication (`host`, `user`, `token_name`, `token_value`, `verify_ssl`).
- Inspect cluster, nodes, QEMU VMs, and LXC containers:
  - Privileged LXC containers (`unprivileged` set to `0` or missing) -> `HIGH`.
  - Risky LXC features enabled on privileged containers (e.g., `nesting=1`, `keyctl=1`) -> `HIGH`.
  - Firewall disabled at Datacenter level, Node level, or individual VM/LXC network interface level -> `MEDIUM`.
  - Overly permissive API tokens without privilege separation (`privsep=0`) -> `MEDIUM`.

### D. HTML & PDF Report Generator (`reporter/generator.py` & `reporter/template.html`)
- Build a modern, clean single-file HTML report with embedded CSS (no external CDN dependencies so it works completely offline).
- Include:
  - Executive header (Hostname, Scan Timestamp, Total Findings).
  - Severity summary cards (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) with distinct color coding.
  - Filterable or grouped findings table/cards showing Category, Target, Severity badge, Technical Description, and Remediation block.
- Save HTML to `output_dir` with timestamped filename (`aegis_report_YYYYMMDD_HHMMSS.html`).
- If `--pdf` flag or `generate_pdf: true` is set, export a matching `.pdf` file using `WeasyPrint`.

## 5. CLI & Configuration (`main.py` & `config.example.yaml`)
- Provide a `typer` CLI with commands:
  - `scan`: `--config / -c` (default `config.yaml`), `--pdf` (boolean flag), `--output / -o` (optional override).
  - `init-config`: copies `config.example.yaml` to `config.yaml` if not present.
- Ensure fault tolerance: if Docker is not installed, Proxmox is disabled/unreachable, or a network host times out, log a clear `rich` warning and continue executing the remaining modules without crashing.
- Include a comprehensive `README.md` with installation steps, Proxmox API token setup instructions, and usage examples.