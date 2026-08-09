"""
Masscan Scan Module
Ultra-fast TCP port scanning via Masscan.
https://github.com/robertdavidgraham/masscan

Masscan emits one JSON record per (IP, port) pair, so results are merged by IP
before being returned as Inventa asset dicts.

Masscan requires raw-socket access (root/sudo on Linux).  The module detects
whether it is running as root and prepends sudo automatically if not.  If sudo
is unavailable the scan is skipped with a clear message.

Scan profiles match Inventa's low/medium/high convention:
  low    — common 13 ports, rate 1 000 pps   (stealth-safe)
  medium — top 10 000 ports, rate 5 000 pps  (default)
  high   — all 65 535 ports, rate 25 000 pps (fast, noisy)

Tool detection order:
  1. System PATH  (masscan already installed)
  2. tools/masscan/masscan binary  (placed by install.sh)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from modules.platform_compat import raw_socket_prefix


SCAN_PROFILES: Dict[str, Dict] = {
    "low": {
        "ports": "21,22,23,25,53,80,110,143,443,445,3389,8080,8443",
        "rate":  "1000",
    },
    "medium": {
        "ports": "1-10000",
        "rate":  "5000",
    },
    "high": {
        "ports": "1-65535",
        "rate":  "25000",
    },
}


# ── Public entry point ────────────────────────────────────────────────────────

def run_masscan(targets: List[str], profile: str, out_dir: Path) -> List[Dict]:
    """
    Run Masscan against all targets and return merged asset dicts.
    """
    binary = _find_binary()
    if not binary:
        print("  [!] masscan binary not found — install it or place in tools/masscan/")
        print("      apt-get install masscan  |  https://github.com/robertdavidgraham/masscan/releases")
        return []

    cmd_prefix = _root_prefix(binary)
    if cmd_prefix is None:
        print("  [!] masscan requires root privileges; neither root nor sudo is available")
        return []

    cfg = SCAN_PROFILES.get(profile, SCAN_PROFILES["medium"])
    out_dir.mkdir(parents=True, exist_ok=True)
    targets_file = out_dir / "masscan_targets.txt"
    targets_file.write_text("\n".join(targets), encoding="utf-8")
    json_out = out_dir / "masscan_scan.json"

    cmd = cmd_prefix + [
        "-iL",    str(targets_file),
        "-p",     cfg["ports"],
        "--rate", cfg["rate"],
        "-oJ",    str(json_out),
        "--open-only",
    ]
    print(f"  [*] Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        if result.returncode != 0:
            stderr = result.stderr.strip()
            stdout = result.stdout.strip()
            details = stderr or stdout or "no diagnostic output"
            print(f"  [!] masscan exit {result.returncode}: {details[:300]}")

        if not json_out.exists() or json_out.stat().st_size == 0:
            print("  [!] masscan produced no output (no open ports found or scan failed)")
            return []

        return _parse_masscan_json(json_out)

    except subprocess.TimeoutExpired:
        print("  [!] masscan timed out after 10 minutes")
        return []
    except Exception as e:
        print(f"  [!] masscan failed: {e}")
        return []


# ── JSON parser ───────────────────────────────────────────────────────────────

def _parse_masscan_json(json_file: Path) -> List[Dict]:
    """
    Parse masscan -oJ output.  Masscan emits one record per open (IP, port),
    so we merge by IP and build the standard Inventa asset shape.

    Handles the quirky masscan JSON format:  the file starts with '[' and each
    record is on its own line, separated by commas — but the closing ']' may
    be missing if masscan was interrupted.
    """
    raw_text = json_file.read_text(encoding="utf-8", errors="ignore").strip()

    # Robustly collect all JSON objects regardless of wrapper
    records: List[Dict] = []
    try:
        # Try straight parse first (complete, well-formed file)
        parsed = json.loads(raw_text)
        if isinstance(parsed, list):
            records = parsed
        elif isinstance(parsed, dict):
            records = [parsed]
    except json.JSONDecodeError:
        # Fallback: strip the outer [ ] and split on lines, ignoring leading commas
        for line in raw_text.splitlines():
            line = line.strip().lstrip(",").rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict) and "ip" in obj:
                    records.append(obj)
            except json.JSONDecodeError:
                continue

    # Merge records by IP
    by_ip: Dict[str, Dict] = defaultdict(lambda: {
        "source": "masscan",
        "ip": "",
        "ports": [],
        "services": [],
        "hostname": None,
    })

    for rec in records:
        ip = rec.get("ip")
        if not ip:
            continue
        asset = by_ip[ip]
        asset["ip"] = ip

        for p in rec.get("ports", []):
            port_num = str(p.get("port", ""))
            proto    = p.get("proto", "tcp")
            status   = p.get("status", "")
            if status != "open":
                continue
            port_entry = {"port": port_num, "protocol": proto, "service": None, "version": None}
            # Avoid duplicates
            if port_entry not in asset["ports"]:
                asset["ports"].append(port_entry)

    assets = [v for v in by_ip.values() if v["ports"]]
    return assets


# ── Helpers ───────────────────────────────────────────────────────────────────

def _find_binary() -> Optional[str]:
    if shutil.which("masscan"):
        return "masscan"
    local = Path(__file__).parent.parent / "tools" / "masscan" / "masscan"
    if local.exists():
        return str(local)
    return None


def _root_prefix(binary: str) -> Optional[List[str]]:
    """Return the command prefix needed to run masscan with raw-socket access."""
    return raw_socket_prefix(binary)
