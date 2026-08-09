"""Wrapper for initstring/cloud_enum public cloud OSINT enumeration."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlparse


def run_cloud_enum_external(
    keywords: Iterable[str],
    out_dir: Path,
    provider: str = "all",
    quickscan: bool = True,
    threads: int = 5,
    nameserver: str = "1.1.1.1",
    tool_path: Optional[str] = None,
) -> List[Dict]:
    """Run initstring/cloud_enum and convert JSONL findings into Inventa assets."""
    keyword_list = _clean_keywords(keywords)
    if not keyword_list:
        print("  [!] cloud_enum skipped: provide --cloud-keyword or domain/website targets")
        return []

    script = _find_cloud_enum(tool_path)
    if not script:
        print("  [!] initstring/cloud_enum not found")
        print("      Install: git clone https://github.com/initstring/cloud_enum.git tools/cloud_enum")
        print("      Then:    python3 -m pip install -r tools/cloud_enum/requirements.txt")
        return []

    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "cloud_enum_findings.jsonl"
    if log_path.exists():
        log_path.unlink()

    cmd = [
        sys.executable,
        str(script),
        *[part for keyword in keyword_list for part in ("-k", keyword)],
        "-t",
        str(threads),
        "-ns",
        nameserver,
        "-l",
        str(log_path),
        "-f",
        "json",
    ]
    if quickscan:
        cmd.append("--quickscan")

    provider = (provider or "all").lower()
    if provider != "all":
        if provider != "aws":
            cmd.append("--disable-aws")
        if provider != "azure":
            cmd.append("--disable-azure")
        if provider != "gcp":
            cmd.append("--disable-gcp")

    print(f"  [*] Running initstring/cloud_enum for {', '.join(keyword_list)}")
    try:
        result = subprocess.run(
            cmd,
            cwd=str(script.parent),
            capture_output=True,
            text=True,
            timeout=900,
        )
    except subprocess.TimeoutExpired:
        print("  [!] cloud_enum timed out")
        return []
    except Exception as e:
        print(f"  [!] cloud_enum failed: {e}")
        return []

    if result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        print(f"  [!] cloud_enum exited with {result.returncode}: {details[:300]}")

    assets = _parse_cloud_enum_log(log_path)
    print(f"  [✓] cloud_enum produced {len(assets)} finding asset(s)")
    return assets


def _find_cloud_enum(tool_path: Optional[str] = None) -> Optional[Path]:
    candidates = []
    if tool_path:
        candidates.append(Path(tool_path))
    candidates.extend([
        Path("tools/cloud_enum/cloud_enum.py"),
        Path("tools/cloud_enum/cloud_enum"),
        Path("cloud_enum.py"),
    ])
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()

    binary = shutil.which("cloud_enum") or shutil.which("cloud_enum.py")
    return Path(binary).resolve() if binary else None


def _clean_keywords(keywords: Iterable[str]) -> List[str]:
    cleaned = []
    seen = set()
    for value in keywords or []:
        value = str(value).strip()
        if not value:
            continue
        parsed = urlparse(value)
        if parsed.hostname:
            value = parsed.hostname
        value = value.lower().strip(".")
        if value and value not in seen:
            cleaned.append(value)
            seen.add(value)
    return cleaned


def _parse_cloud_enum_log(log_path: Path) -> List[Dict]:
    if not log_path.exists():
        return []

    assets = []
    for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("####"):
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue
        asset = _finding_to_asset(finding)
        if asset:
            assets.append(asset)
    return assets


def _finding_to_asset(finding: Dict) -> Optional[Dict]:
    target = finding.get("target")
    if not target:
        return None
    provider = (finding.get("platform") or _provider_from_target(target)).lower()
    resource_type = _resource_type(finding.get("msg", ""), target)
    hostname = urlparse(target).hostname or target
    return {
        "source": "cloud_enum",
        "cloud_provider": provider,
        "resource_type": resource_type,
        "resource_id": target,
        "name": hostname.split(".")[0] if hostname else target,
        "hostname": hostname,
        "fqdn": hostname,
        "url": target if str(target).startswith(("http://", "https://")) else None,
        "ip": None,
        "public_ip": None,
        "ports": [],
        "services": [resource_type],
        "externally_exposed": finding.get("access") == "public",
        "cloud_enum": finding,
    }


def _provider_from_target(target: str) -> str:
    target = target.lower()
    if "amazonaws.com" in target or "awsapps.com" in target:
        return "aws"
    if "azure" in target or "windows.net" in target or "cloudapp.net" in target:
        return "azure"
    if "googleapis.com" in target or "appspot.com" in target or "firebaseio.com" in target:
        return "gcp"
    return "unknown"


def _resource_type(message: str, target: str) -> str:
    text = f"{message} {target}".lower()
    if "bucket" in text or "storage" in text or "blob" in text:
        return "storage"
    if "container" in text:
        return "storage_container"
    if "database" in text or "firebase" in text:
        return "database"
    if "virtual machine" in text or "cloudapp" in text:
        return "vm_dns"
    if "website" in text or "web app" in text or "azurewebsites" in text:
        return "web_app"
    if "function" in text:
        return "function"
    return "cloud_resource"
