"""
ZMap Scan Module
Fast single-packet TCP SYN scanning via ZMap.

ZMap scans one port at a time, so this module runs one pass per configured port
and merges responders into the standard Inventa asset shape.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from modules.platform_compat import raw_socket_prefix


SCAN_PROFILES: Dict[str, Dict[str, List[int]]] = {
    "low": {
        "ports": [80, 443, 22, 21, 25, 53, 8080, 8443],
    },
    "medium": {
        "ports": [80, 443, 22, 21, 25, 53, 110, 143, 445, 993, 995, 3306, 3389, 8080, 8443],
    },
    "high": {
        "ports": [80, 443, 22, 21, 23, 25, 53, 110, 143, 161, 389, 445, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443],
    },
}


def run_zmap(targets: List[str], profile: str, out_dir: Path) -> List[Dict]:
    binary = _find_binary()
    if not binary:
        print("  [!] zmap binary not found — install it or place it in tools/zmap/")
        print("      https://github.com/zmap/zmap")
        return []

    if not targets:
        return []

    cmd_prefix = _root_prefix(binary)
    if cmd_prefix is None:
        print("  [!] zmap requires root privileges; neither root nor sudo is available")
        return []

    cfg = SCAN_PROFILES.get(profile, SCAN_PROFILES["medium"])
    out_dir.mkdir(parents=True, exist_ok=True)
    targets_file = out_dir / "zmap_targets.txt"
    targets_file.write_text("\n".join(targets), encoding="utf-8")

    assets_by_ip = defaultdict(lambda: {
        "source": "zmap",
        "ip": "",
        "hostname": None,
        "ports": [],
        "services": [],
    })

    for port in cfg["ports"]:
        output_file = out_dir / f"zmap_port_{port}.csv"
        cmd = cmd_prefix + [
            "-p", str(port),
            "-w", str(targets_file),
            "-f", "saddr",
            "-o", str(output_file),
            "-q",
        ]
        print(f"  [*] Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode != 0:
                stderr = result.stderr.strip()
                stdout = result.stdout.strip()
                details = stderr or stdout or "no diagnostic output"
                print(f"  [!] zmap port {port} exited with {result.returncode}: {details[:300]}")
                continue
            if not output_file.exists():
                continue

            for line in output_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                ip = line.strip()
                if not ip or ip == "saddr":
                    continue
                asset = assets_by_ip[ip]
                asset["ip"] = ip
                port_entry = {
                    "port": str(port),
                    "protocol": "tcp",
                    "service": None,
                    "version": None,
                }
                if port_entry not in asset["ports"]:
                    asset["ports"].append(port_entry)
        except subprocess.TimeoutExpired:
            print(f"  [!] zmap timed out on port {port}")
        except Exception as e:
            print(f"  [!] zmap failed on port {port}: {e}")

    return [asset for asset in assets_by_ip.values() if asset["ports"]]


def _find_binary() -> Optional[str]:
    if shutil.which("zmap"):
        return "zmap"
    local = Path(__file__).parent.parent / "tools" / "zmap" / "zmap"
    if local.exists():
        return str(local)
    return None


def _root_prefix(binary: str) -> Optional[List[str]]:
    return raw_socket_prefix(binary)
