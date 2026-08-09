"""Wrapper for Codingo/VHostScan virtual host discovery."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlparse


def run_vhostscan(
    targets: Iterable[str],
    out_dir: Path,
    base_host: Optional[str] = None,
    port: int = 80,
    ssl: bool = False,
    wordlist: Optional[str] = None,
    tool_path: Optional[str] = None,
) -> List[Dict]:
    """Run VHostScan and convert JSON output into Inventa web assets."""
    target_list = _clean_targets(targets)
    if not target_list:
        print("  [!] VHostScan skipped: no host targets supplied")
        return []

    runner = _find_vhostscan(tool_path)
    if not runner:
        print("  [!] VHostScan not found")
        print("      Install: git clone https://github.com/codingo/VHostScan.git tools/VHostScan")
        print("      Then:    python3 -m pip install -e tools/VHostScan")
        return []

    out_dir.mkdir(parents=True, exist_ok=True)
    assets: List[Dict] = []

    for target in target_list:
        output_path = out_dir / f"vhostscan_{_safe_name(target)}_{port}.json"
        if output_path.exists():
            output_path.unlink()

        cmd = _build_command(runner, target, output_path, base_host, port, ssl, wordlist)
        print(f"  [*] Running VHostScan against {target}:{port}")

        try:
            result = subprocess.run(
                cmd,
                cwd=str(_runner_cwd(runner)),
                capture_output=True,
                text=True,
                timeout=900,
            )
        except subprocess.TimeoutExpired:
            print(f"  [!] VHostScan timed out for {target}")
            continue
        except Exception as e:
            print(f"  [!] VHostScan failed for {target}: {e}")
            continue

        if result.returncode != 0:
            details = (result.stderr or result.stdout or "").strip()
            print(f"  [!] VHostScan exited with {result.returncode}: {details[:300]}")
            continue

        assets.extend(_parse_vhostscan_json(output_path))

    print(f"  [✓] VHostScan produced {len(assets)} virtual host asset(s)")
    return assets


def _find_vhostscan(tool_path: Optional[str] = None) -> Optional[Path]:
    candidates = []
    if tool_path:
        candidates.append(Path(tool_path))
    candidates.extend([
        Path("tools/VHostScan/VHostScan/VHostScan.py"),
        Path("tools/VHostScan/vhostscan.py"),
        Path("VHostScan.py"),
    ])
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()

    binary = shutil.which("VHostScan") or shutil.which("vhostscan")
    return Path(binary).resolve() if binary else None


def _build_command(
    runner: Path,
    target: str,
    output_path: Path,
    base_host: Optional[str],
    port: int,
    ssl: bool,
    wordlist: Optional[str],
) -> List[str]:
    if runner.name.endswith(".py"):
        if runner.parent.name == "VHostScan":
            cmd = [sys.executable, "-m", "VHostScan.VHostScan"]
        else:
            cmd = [sys.executable, str(runner)]
    else:
        cmd = [str(runner)]

    cmd.extend(["-t", target, "-p", str(port), "-oJ", str(output_path), "--no-lookups"])
    if base_host:
        cmd.extend(["-b", base_host])
    if ssl:
        cmd.append("--ssl")
    if wordlist:
        cmd.extend(["-w", str(Path(wordlist).resolve())])
    return cmd


def _runner_cwd(runner: Path) -> Path:
    if runner.name.endswith(".py") and runner.parent.name == "VHostScan":
        return runner.parent.parent
    return runner.parent if runner.name.endswith(".py") else Path.cwd()


def _parse_vhostscan_json(path: Path) -> List[Dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []

    target = data.get("Target")
    port = str(data.get("Port") or "80")
    scheme = "https" if data.get("SSL") else "http"
    results = data.get("Result") or {}

    assets = []
    for hostname, detail in results.items():
        if not hostname:
            continue
        code = detail.get("Code")
        assets.append({
            "source": "vhostscan",
            "hostname": hostname,
            "fqdn": hostname,
            "ip": target,
            "public_ip": None,
            "url": f"{scheme}://{hostname}" + ("" if port in ("80", "443") else f":{port}"),
            "ports": [{
                "port": port,
                "protocol": "tcp",
                "service": scheme,
            }],
            "services": [scheme, "virtual_host"],
            "vhostscan": {
                "target": target,
                "status_code": code,
                "hash": detail.get("Hash"),
                "headers": detail.get("Headers") or {},
            },
        })
    return assets


def _clean_targets(targets: Iterable[str]) -> List[str]:
    cleaned = []
    seen = set()
    for value in targets or []:
        value = str(value).strip()
        if not value:
            continue
        parsed = urlparse(value)
        if parsed.hostname:
            value = parsed.hostname
        if value not in seen:
            cleaned.append(value)
            seen.add(value)
    return cleaned


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ".-" else "_" for ch in value)[:80]
