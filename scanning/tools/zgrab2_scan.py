"""
ZGrab2 Scan Module
Fast application-layer scanning using zgrab2.

This module focuses on website/domain and web-service verification. It accepts
domains, hostnames, or IPs and uses zgrab2's stdin input format.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Iterable, List, Optional


DEFAULT_MODULE = "http"


def run_zgrab2(
    targets: Iterable[str],
    out_dir: Path,
    module: str = DEFAULT_MODULE,
    use_tls: bool = True,
) -> List[Dict]:
    binary = _find_binary()
    if not binary:
        print("  [!] zgrab2 binary not found — install it or place it in tools/zgrab2/")
        print("      https://github.com/zmap/zgrab2")
        return []

    normalized_targets = [str(t).strip() for t in targets if str(t).strip()]
    if not normalized_targets:
        return []

    input_file = out_dir / "zgrab2_input.csv"
    output_file = out_dir / f"zgrab2_{module}.jsonl"
    input_file.write_text("\n".join(normalized_targets), encoding="utf-8")

    cmd = [
        binary,
        module,
        "--input-file", str(input_file),
        "--output-file", str(output_file),
    ]

    if module == "http" and use_tls:
        cmd.append("--use-https")

    print(f"  [*] Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0 and result.stderr.strip():
            print(f"  [!] zgrab2 exited with {result.returncode}: {result.stderr.strip()[:200]}")
        if not output_file.exists():
            return []
        return _parse_zgrab2_jsonl(output_file, module)
    except subprocess.TimeoutExpired:
        print("  [!] zgrab2 timed out after 10 minutes")
        return []
    except Exception as e:
        print(f"  [!] zgrab2 failed: {e}")
        return []


def _parse_zgrab2_jsonl(output_file: Path, module: str) -> List[Dict]:
    assets: "OrderedDict[str, Dict]" = OrderedDict()

    for line in output_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue

        ip = row.get("ip")
        domain = row.get("domain")
        data = (row.get("data") or {}).get(module) or {}
        if data.get("status") != "success":
            continue

        key = ip or domain
        if not key:
            continue

        asset = assets.setdefault(key, {
            "source": "zgrab2",
            "ip": ip,
            "hostname": domain,
            "endpoint": domain,
            "ports": [],
            "services": [],
        })

        port = data.get("port")
        protocol = data.get("protocol", module)
        if port is not None:
            port_entry = {
                "port": str(port),
                "protocol": "tcp",
                "service": module,
                "version": None,
            }
            if port_entry not in asset["ports"]:
                asset["ports"].append(port_entry)
        if module not in asset["services"]:
            asset["services"].append(module)

        asset.setdefault("zgrab2", {})[module] = data
    return list(assets.values())


def _find_binary() -> Optional[str]:
    if shutil.which("zgrab2"):
        return "zgrab2"
    local = Path(__file__).resolve().parents[2] / "tools" / "zgrab2" / "zgrab2"
    if local.exists():
        return str(local)
    return None
