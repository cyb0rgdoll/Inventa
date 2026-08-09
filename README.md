<p align="center">
  <img src="docs/screenshot.svg" alt="Inventa CLI" width="600">
</p>

# Inventa

Inventa is a defensive asset discovery and inventory tool for authorized environments. It helps identify hosts, open services, device details, domains, web exposure, and cloud assets, then saves the findings in practical report formats.

The purpose of Inventa is to make discovery work simpler: gather a clear picture of what exists in scope, reduce manual command juggling, and produce evidence that can be reviewed or included in security documentation.

Inventa performs active reconnaissance and network scanning. It is intended
solely for **authorized** security testing, asset discovery, research, and
educational use. **Use it only against systems and networks you own or have
explicit, written permission to assess.**

## What Inventa Does

- Discovers live hosts and open ports with nmap-based scanning.
- Enriches assets with banners, fingerprints, MAC/vendor data, SNMP details, and device type where available.
- Supports domain, web, OSINT, and cloud-focused workflows.
- Generates JSON, HTML, CSV, and inventory outputs.
- Provides a simple menu and short commands so users do not need to remember long flag combinations.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Inventa also needs external scanners (nmap, masscan) and, optionally, several
recon tools. These are **not** bundled with the repository — install them
separately:

```bash
bash scripts/install-scanning-tools.sh   # nmap + masscan + NSE
```

See **[SETUP_TOOLS.md](SETUP_TOOLS.md)** for the full list, including the
optional external recon tools and the `zgrab2` submodule.

## Quick Start

Run the menu:

```bash
python3 inventa.py
```

Use **Configuration** to create:

- `scope.txt`: authorized CIDR ranges
- `targets.txt`: IPs, hosts, or CIDR ranges to assess
- `.env`: optional API keys

## Simple Commands

```bash
python3 inventa.py quick
python3 inventa.py scan
python3 inventa.py inventory
python3 inventa.py domain example.com
python3 inventa.py web example.com
python3 inventa.py cloud aws
python3 inventa.py results
python3 inventa.py doctor
```

## Results

Scan output is saved under `results/` and can include:

- `inventa_data_*.json`
- `inventa_report_*.html`
- `inventa_report_*.csv`
- inventory CSV and SQLite files

Open saved results with:

```bash
python3 inventa.py results
```

## Advanced Options

Most users should only need the menu or simple commands. Advanced flags are still available:

```bash
python3 inventa.py --advanced-help
```

## Safety

Only scan systems you own or have explicit permission to assess (see
**Authorized Use** above). Keep credentials, generated evidence, local
archives, and unrelated workstation tools out of Git. API keys live in a local
`.env` file, which is git-ignored — never commit it. `.env.example` shows the
supported variable names with empty values.

## Documentation

- [SETUP_TOOLS.md](SETUP_TOOLS.md) — installing nmap, masscan, and optional recon tools
- [QUICK_START.md](QUICK_START.md) — fastest path to a first scan
- [SECURITY.md](SECURITY.md) — how to report a vulnerability
- [CONTRIBUTING.md](CONTRIBUTING.md) — development setup and contribution rules
- [LICENSE](LICENSE)
  

You are responsible for ensuring your use complies with all applicable laws,
regulations, contracts, policies, and authorization boundaries. Unauthorized
scanning may be illegal. The authors and contributors accept no liability for
misuse or for any damage caused by this tool.
