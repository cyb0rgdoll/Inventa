#!/usr/bin/env python3
"""
Minimal Inventa endpoint agent.

Run on an authorised endpoint to create a local JSON inventory file:
  python3 agent/inventa_agent.py -o agent_inventory.json
Then import it into Inventa:
  python3 inventa.py -s scope.txt -t targets.txt --agent-import agent_inventory.json --inventory
"""

from __future__ import annotations

import argparse
import json
import platform
import socket
import subprocess
from datetime import datetime
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Inventa endpoint inventory agent")
    parser.add_argument("-o", "--output", default="agent_inventory.json")
    args = parser.parse_args()
    inventory = collect_inventory()
    Path(args.output).write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    print(args.output)


def collect_inventory() -> dict:
    return {
        "agent_version": "0.1",
        "collected_at": datetime.now().isoformat(timespec="seconds"),
        "hostname": socket.gethostname(),
        "primary_ip": _primary_ip(),
        "platform": platform.platform(),
        "os": _os_release(),
        "architecture": platform.machine(),
        "running_services": _running_services(),
        "installed_software": _installed_software(),
    }


def _primary_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except Exception:
        return ""


def _os_release() -> str:
    output = _run(["cat", "/etc/os-release"])
    return output if output else platform.platform()


def _running_services() -> list:
    output = _run(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"])
    if output:
        return [line.split()[0] for line in output.splitlines()[:100] if line.split()]
    output = _run(["ps", "-eo", "comm="])
    return sorted(set(output.splitlines()))[:100] if output else []


def _installed_software() -> list:
    output = _run(["dpkg-query", "-W", "-f=${Package} ${Version}\\n"])
    if output:
        return output.splitlines()[:200]
    output = _run(["rpm", "-qa"])
    return output.splitlines()[:200] if output else []


def _run(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except Exception:
        return ""
    return (result.stdout or "").strip()


if __name__ == "__main__":
    main()
