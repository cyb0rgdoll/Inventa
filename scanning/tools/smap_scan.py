"""
Smap Scan Module
Passive port scanning using Shodan's internet-wide data via Smap.
https://github.com/s0md3v/Smap

Smap is a drop-in nmap replacement: it accepts the same flags but instead of
sending packets it queries Shodan's free internetdb.shodan.io API.
No Shodan API key is required.  Private/RFC-1918 IPs return no results.

Smap outputs standard nmap XML, so parse_nmap_xml from active_scan is reused.

Tool detection order:
  1. System PATH  (smap already installed)
  2. tools/smap/smap binary  (placed by install.sh)
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional


# ── Public entry point ────────────────────────────────────────────────────────

def run_smap(targets: List[str], out_dir: Path) -> List[Dict]:
    """
    Run Smap against all targets and return asset dicts in the Inventa format.
    Reuses active_scan.parse_nmap_xml — Smap output is nmap-compatible XML.
    """
    binary = _find_binary()
    if not binary:
        print("  [!] smap binary not found — install it or place in tools/smap/")
        print("      go install github.com/s0md3v/smap/cmd/smap@v0.2.0-rc")
        return []

    out_dir.mkdir(parents=True, exist_ok=True)
    targets_file = out_dir / "smap_targets.txt"
    targets_file.write_text("\n".join(targets), encoding="utf-8")
    xml_out = out_dir / "smap_scan.xml"

    cmd = [binary, "-iL", str(targets_file), "-oX", str(xml_out)]
    print(f"  [*] Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            stderr = result.stderr.strip()
            stdout = result.stdout.strip()
            details = stderr or stdout or "no diagnostic output"
            print(f"  [!] smap exit {result.returncode}: {details[:300]}")

        if not xml_out.exists() or xml_out.stat().st_size == 0:
            print("  [!] smap produced no output file")
            return []

        from modules.active_scan import parse_nmap_xml
        assets = parse_nmap_xml(xml_out)

        # Tag each asset so downstream modules know it came from smap (passive)
        for a in assets:
            a["source"] = "smap"
            a.setdefault("scan_method", "passive_shodan")

        return assets

    except subprocess.TimeoutExpired:
        print("  [!] smap timed out after 5 minutes")
        return []
    except Exception as e:
        print(f"  [!] smap failed: {e}")
        return []


# ── Helpers ───────────────────────────────────────────────────────────────────

def _find_binary() -> Optional[str]:
    if shutil.which("smap"):
        return "smap"
    local = Path(__file__).parent.parent / "tools" / "smap" / "smap"
    if local.exists():
        return str(local)
    return None
