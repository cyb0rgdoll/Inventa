"""
Striker External Workflow
Runs s0md3v/Striker against website/domain targets and converts its JSON dataset
into Inventa asset dictionaries.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from modules.platform_compat import python_executable


def run_striker(domains: Iterable[str], out_dir: Path) -> List[Dict]:
    tool_dir = Path(__file__).parent.parent / "tools" / "Striker"
    script = tool_dir / "striker.py"
    if not script.exists():
        print("  [!] Striker not found — expected tools/Striker/striker.py")
        return []

    scan_dir = out_dir / "striker"
    scan_dir.mkdir(parents=True, exist_ok=True)

    assets: List[Dict] = []
    for domain in sorted({str(d).strip().lower() for d in domains if str(d).strip()}):
        raw_file = scan_dir / f"{domain}_striker.txt"
        try:
            result = subprocess.run(
                [python_executable(), str(script), domain],
                cwd=str(tool_dir),
                capture_output=True,
                text=True,
                timeout=900,
            )
            output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
            raw_file.write_text(output, encoding="utf-8", errors="ignore")
            parsed = _extract_json_dataset(output)
            if not parsed:
                print(f"  [!] Striker produced no parseable JSON for {domain}")
                continue
            assets.extend(_dataset_to_assets(domain, parsed, raw_file))
        except subprocess.TimeoutExpired:
            print(f"  [!] Striker timed out for {domain}")
        except Exception as e:
            print(f"  [!] Striker failed for {domain}: {e}")

    return assets


def _extract_json_dataset(output: str) -> Optional[Dict]:
    start = output.find("{")
    end = output.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(output[start : end + 1])
    except json.JSONDecodeError:
        return None


def _dataset_to_assets(domain: str, dataset: Dict, raw_file: Path) -> List[Dict]:
    assets: List[Dict] = []
    for host, details in dataset.items():
        ports = []
        for port in details.get("ports", []) or []:
            service = "https" if str(port) == "443" else "http" if str(port) == "80" else None
            ports.append({
                "port": str(port),
                "protocol": "tcp",
                "service": service,
                "version": None,
            })

        services = list(details.get("technologies", []) or [])
        cms = details.get("cms")
        if cms and cms not in services:
            services.append(cms)

        assets.append({
            "source": "striker",
            "hostname": host,
            "fqdn": host,
            "domain": domain,
            "ip": details.get("ip"),
            "ports": ports,
            "services": services,
            "endpoint": f"{details.get('schema', 'http')}://{host}",
            "web_inspection": {
                f"{details.get('schema', 'http')}://{host}": {
                    "technologies": list(details.get("technologies", []) or []),
                    "forms": list(details.get("forms", []) or []),
                    "striker": {
                        "cms": cms,
                        "outdated_libs": list(details.get("outdated_libs", []) or []),
                        "all_urls": list(details.get("all_urls", []) or []),
                        "raw_output_file": str(raw_file),
                    },
                }
            },
        })
    return assets
