"""
ReconSpider External Workflow
Runs ReconSpider in automated domain mode and stores its raw output for review.

ReconSpider is menu-driven and not designed as a stable machine-readable CLI, so
this integration is best-effort and primarily captures its textual findings.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List

from modules.platform_compat import python_executable


def run_reconspider(domains: Iterable[str], assets: List[Dict], out_dir: Path) -> List[Dict]:
    tool_dir = Path(__file__).parent.parent / "tools" / "reconspider"
    script = tool_dir / "reconspider.py"
    if not script.exists():
        print("  [!] ReconSpider not found — expected tools/reconspider/reconspider.py")
        return assets

    _ensure_reconspider_config(tool_dir)

    scan_dir = out_dir / "reconspider"
    scan_dir.mkdir(parents=True, exist_ok=True)

    domains = sorted({str(d).strip().lower() for d in domains if str(d).strip()})
    if not domains:
        return assets

    for domain in domains:
        raw_file = scan_dir / f"{domain}_reconspider.txt"
        input_script = "2\n{domain}\n80\n1\n2\n3\n4\n10\n11\n12\n99\n0\n".format(domain=domain)
        try:
            result = subprocess.run(
                [python_executable(), str(script)],
                cwd=str(tool_dir),
                input=input_script,
                capture_output=True,
                text=True,
                timeout=900,
            )
            output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
            raw_file.write_text(output, encoding="utf-8", errors="ignore")
            _attach_reconspider_output(assets, domain, raw_file)
        except subprocess.TimeoutExpired:
            print(f"  [!] ReconSpider timed out for {domain}")
        except Exception as e:
            print(f"  [!] ReconSpider failed for {domain}: {e}")

    return assets


def _ensure_reconspider_config(tool_dir: Path) -> None:
    config_path = tool_dir / "core" / "config.py"
    if not config_path.exists():
        shodan_api = os.environ.get("SHODAN_API_KEY", "")
        config_path.write_text(f'shodan_api = "{shodan_api}"\n', encoding="utf-8")


def _attach_reconspider_output(assets: List[Dict], domain: str, raw_file: Path) -> None:
    matched = False
    for asset in assets:
        candidates = {
            str(asset.get("domain") or "").lower(),
            str(asset.get("hostname") or "").lower(),
            str(asset.get("fqdn") or "").lower(),
        }
        if domain in candidates or any(c.endswith(f".{domain}") for c in candidates if c):
            asset.setdefault("external_recon", {})["reconspider"] = {
                "status": "completed",
                "raw_output_file": str(raw_file),
            }
            matched = True

    if not matched:
        assets.append({
            "source": "reconspider",
            "hostname": domain,
            "fqdn": domain,
            "domain": domain,
            "ports": [],
            "services": [],
            "external_recon": {
                "reconspider": {
                    "status": "completed",
                    "raw_output_file": str(raw_file),
                }
            },
        })
