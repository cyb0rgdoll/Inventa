# Inventa Quick Start

Inventa is easiest to use from the menu:

```bash
python3 inventa.py
```

Use **Configuration** first to create:

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

## What To Use

Use `quick` for a fast first look at live hosts and open services.

Use `scan` for the normal balanced workflow. It creates JSON, HTML, and CSV output under `results/`.

Use `inventory` when you want MAC address, vendor, SNMP, device type, and SQLite inventory output.

Use `domain example.com` for passive domain and subdomain reconnaissance.

Use `web example.com` for website inspection.

Use `cloud aws`, `cloud azure`, `cloud gcp`, or `cloud all` for configured cloud account inventory.

## Advanced Use

Most users should not need flags. Advanced options are still available:

```bash
python3 inventa.py --advanced-help
python3 inventa.py examples
```

## Results

Open reports from the menu or run:

```bash
python3 inventa.py results
```
