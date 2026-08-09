"""Portable environment checks for Inventa."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

from modules.platform_compat import is_windows, is_wsl

Check = Tuple[str, bool, str, bool]


def run_doctor(results_dir: str = "results") -> int:
    checks: List[Check] = []

    checks.append(("Operating system", True, _platform_label(), True))
    checks.append(("Python", sys.version_info >= (3, 9), sys.version.split()[0], True))
    checks.append(("Results directory", _can_write_results(results_dir), str(Path(results_dir).resolve()), True))

    for binary in ("nmap",):
        path = shutil.which(binary)
        checks.append((f"{binary} in PATH", bool(path), path or "not found", True))

    for binary in ("amass", "subfinder", "assetfinder", "aws", "az"):
        path = shutil.which(binary)
        checks.append((f"{binary} in PATH", bool(path), path or "not found", False))

    cloudscraper_path = Path(__file__).parent.parent / "tools" / "CloudScraper" / "CloudScraper.py"
    checks.append(("CloudScraper optional", cloudscraper_path.exists(), str(cloudscraper_path), False))

    checks.append(("AWS CLI configured", _command_ok(["aws", "sts", "get-caller-identity"]), "aws sts get-caller-identity", False))
    checks.append(("Azure CLI configured", _command_ok(["az", "account", "show"]), "az account show", False))

    print("\nInventa Doctor\n" + "=" * 60)
    ok_count = 0
    required_ok = True
    for name, ok, detail, required in checks:
        mark = "[OK]" if ok else ("[!!]" if required else "[--]")
        if ok:
            ok_count += 1
        elif required:
            required_ok = False
        print(f"{mark} {name:<24} {detail}")

    print("=" * 60)
    print(f"{ok_count}/{len(checks)} checks passed")
    print("\nUseful commands:")
    print("  python3 inventa.py quick")
    print("  python3 inventa.py scan")
    print("  python3 inventa.py inventory")
    print("  python3 inventa.py domain example.com")
    print("  python3 inventa.py cloud aws")
    print("  python3 inventa.py -s scope.txt -t targets.txt --exclude exclude.txt")

    return 0 if required_ok else 1


def _platform_label() -> str:
    if is_windows():
        return "Windows"
    if is_wsl():
        return "WSL"
    return sys.platform


def _can_write_results(results_dir: str) -> bool:
    try:
        path = Path(results_dir)
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".inventa_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def _command_ok(cmd: List[str]) -> bool:
    if not shutil.which(cmd[0]):
        return False
    try:
        env = os.environ.copy()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, env=env)
        return result.returncode == 0
    except Exception:
        return False
