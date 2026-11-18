# AegisInfra

**AegisInfra** is a production-ready Python CLI security auditing tool designed for self-hosted infrastructures, homelabs, and small server environments. It audits network exposure, Docker daemon/container posture, and Proxmox VE cluster/guest configurations, then outputs a color-coded terminal summary alongside a standalone, offline-ready HTML report (with optional PDF export).

## Features

- **Network & Port Scanner (`scanner/network.py`)**
  - Concurrent TCP port scanning across IP addresses and CIDR subnets (`ThreadPoolExecutor`).
  - Non-intrusive socket banner grabbing to fingerprint exposed services.
  - Risk-based severity classification (e.g., unencrypted Telnet/FTP, unauthenticated Docker `2375`, exposed Redis `6379` vs. plain HTTP/databases vs. informational SSH/HTTPS).
- **Docker Security Auditor (`scanner/docker_audit.py`)**
  - Detects containers running in `--privileged` mode (`CRITICAL`).
  - Flags sensitive host bind mounts such as `/var/run/docker.sock`, `/`, `/etc`, and `/root` (`HIGH`).
  - Identifies ports bound to `0.0.0.0` / `::` instead of `127.0.0.1` (`MEDIUM`).
  - Flags `network_mode: host` and `pid_mode: host` namespace sharing (`MEDIUM`).
  - Checks for containers running as `root` (`LOW`), outdated images (`LOW`), and mutable `:latest` tags (`INFO`).
- **Proxmox VE Auditor (`scanner/proxmox_audit.py`)**
  - Authenticates via Proxmox API Tokens (`proxmoxer`).
  - Flags privileged LXC containers (`unprivileged=0` or unset) and risky LXC features (`nesting=1`, `keyctl=1`, etc.) on privileged containers (`HIGH`).
  - Checks if the firewall is disabled at the Datacenter, Node, or individual VM/LXC network interface level (`MEDIUM`).
  - Detects API tokens configured without privilege separation (`privsep=0`) (`MEDIUM`).
- **Standalone HTML & Optional PDF Reporting (`reporter/`)**
  - Single-file HTML report with embedded CSS/JS (zero external CDN dependencies).
  - Executive summary, severity cards, category/severity/keyword filtering, and actionable remediation guidance.
  - Optional PDF export via WeasyPrint (gracefully degrades to HTML-only if system GTK/Pango libraries are missing).
- **Fault-Tolerant Execution**
  - Unavailable or disabled modules (e.g., Docker not running, Proxmox unreachable, or host timeouts) log a clear warning and allow the remaining audit modules to complete.

---

## Project Structure

```text
AegisInfra/
├── AegisInfra.bat           # Windows one-click launcher
├── start.py                 # Unified launcher (auto-setup, checks, tests, & scan)
├── main.py                  # Typer CLI entry point & Rich terminal UI
├── healthcheck.py           # Standalone verification & mocked E2E dry-run
├── models.py                # Severity enum, Finding, and AuditReport dataclasses
├── config.example.yaml      # Example configuration template
├── requirements.txt         # Runtime Python dependencies
├── requirements-dev.txt     # Development & test dependencies (pytest)
├── .gitignore
├── README.md
├── scanner/
│   ├── __init__.py
│   ├── network.py           # Concurrent TCP port scanner & banner grabber
│   ├── docker_audit.py      # Docker container & image security auditor
│   └── proxmox_audit.py     # Proxmox VE cluster, node, VM & LXC auditor
├── reporter/
│   ├── __init__.py
│   ├── generator.py         # Jinja2 HTML renderer & optional WeasyPrint PDF exporter
│   └── template.html        # Standalone offline-ready HTML report template
└── tests/                   # pytest unit test suite
```

---

## Installation

### Prerequisites
- **Python 3.11+**
- Optional (for `--pdf` export): WeasyPrint system dependencies (Pango, Cairo, GDK-PixBuf). If these are not installed, AegisInfra still generates the HTML report cleanly and logs a warning.

### Setup

```bash
git clone <your-repo-url> AegisInfra
cd AegisInfra

python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows (PowerShell):
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

---

## Quick Start (Recommended)

### Windows (One-Click)
Double-click **`AegisInfra.bat`** in File Explorer. It automatically creates a `venv` (on first run), installs dependencies from `requirements.txt`, runs all verification checks, executes the audit, and opens the HTML report in your default browser.

### Command Line (Linux / macOS / Windows)
Run the unified launcher to automatically initialize `config.yaml` (if missing), verify dependencies & security checks, run the `pytest` suite, and execute the live audit in a single command:

```bash
python start.py
```

### `start.py` Options
- `--config`, `-c` `PATH` — Path to YAML config file (default: `config.yaml`).
- `--skip-checks` — Skip internal self-checks and `pytest` before running the live scan.
- `--check-only` — Run auto-setup, self-checks, and `pytest` without running the live audit.
- `--pdf` — Export a matching `.pdf` report alongside the `.html` report.
- `--no-browser` — Do not automatically open the generated HTML report in the default browser.

> **Tip:** After the first run creates `config.yaml`, edit it with your target IPs/CIDRs, Docker socket URL, and optional Proxmox VE API token credentials, then re-run `python start.py`.

---

## Direct CLI Usage (`main.py`)

```text
python main.py [COMMAND] [OPTIONS]
```

### Commands

- `init-config`  
  Creates `config.yaml` from `config.example.yaml` if not already present.

- `scan`  
  Runs all enabled audit modules and writes the report(s).
  - `--config`, `-c` `PATH` — Path to YAML config file (default: `config.yaml`).
  - `--pdf` — Export a matching `.pdf` report alongside the `.html` report.
  - `--output`, `-o` `PATH` — Override the `output_dir` defined in `config.yaml`.

### Examples

```bash
# Run scan with default config.yaml
python main.py scan

# Use a custom config file and export both HTML and PDF
python main.py scan --config prod.yaml --pdf

# Save reports to a specific directory
python main.py scan -o /tmp/aegis-reports
```

---

## Proxmox VE API Token Setup

For least-privilege auditing, create a dedicated read-only user and API token in Proxmox VE:

### Option A: Proxmox Web UI
1. Navigate to **Datacenter → Permissions → Users** and click **Add** (e.g., User name: `audit`, Realm: `pve` → `audit@pve`).
2. Navigate to **Datacenter → Permissions → API Tokens** and click **Add**:
   - **User**: `audit@pve`
   - **Token ID**: `aegis-token`
   - **Privilege Separation**: Keep **checked** (`privsep=1`).
   - Copy the generated **Token Secret** immediately (it is only shown once).
3. Navigate to **Datacenter → Permissions → Add → API Token Permission**:
   - **Path**: `/`
   - **API Token**: `audit@pve!aegis-token`
   - **Role**: `PVEAuditor`
4. Also grant `PVEAuditor` to the parent user `audit@pve` on `/` if privilege separation is enabled.

### Option B: Proxmox CLI (`pveum`)
Run on a Proxmox node shell:

```bash
pveum user add audit@pve
pveum aclmod / -user audit@pve -role PVEAuditor
pveum user token add audit@pve aegis-token --privsep 1
pveum aclmod / -token 'audit@pve!aegis-token' -role PVEAuditor
```

Update `config.yaml` with the resulting credentials:

```yaml
proxmox:
  enabled: true
  host: "192.0.2.10"
  port: 8006
  user: "audit@pve"
  token_name: "aegis-token"
  token_value: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  verify_ssl: false
```

---

## Output & Reports

Reports are written to `output_dir` (default `./reports/`) with timestamped filenames:
- `aegis_report_YYYYMMDD_HHMMSS.html`
- `aegis_report_YYYYMMDD_HHMMSS.pdf` (when `--pdf` or `generate_pdf: true` is set)

---

## Testing & Healthcheck

AegisInfra includes both a self-contained verification runner (`healthcheck.py`) and a `pytest` unit test suite (`tests/`).

### 1. Run the Standalone Healthcheck

```bash
python healthcheck.py
```

`healthcheck.py` verifies Python `>= 3.11`, required dependencies, `config.example.yaml` structure, all module imports, and runs a mocked end-to-end dry run (including HTML XSS escaping verification). It exits with `0` if healthy or `1` if any critical check fails. (Missing WeasyPrint system libraries are reported as a non-fatal `WARN`.)

### 2. Run the Unit Test Suite

Install development dependencies and run `pytest`:

```bash
pip install -r requirements-dev.txt
pytest -v
```
