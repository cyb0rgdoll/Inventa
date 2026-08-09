"""
Endpoint agent import support.

The endpoint agent is intentionally simple: it writes JSON locally, and Inventa
imports that JSON during an authorised scan. This avoids exposing an inbound
listener while still supporting agent-style inventory evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List


def import_agent_assets(path: str | Path) -> List[Dict]:
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(f"Agent file not found: {source}")

    data = json.loads(source.read_text(encoding="utf-8"))
    rows = data if isinstance(data, list) else [data]
    assets = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        asset = {
            "source": "inventa-agent",
            "discovery_method": "endpoint agent import",
            "ip": row.get("ip") or row.get("primary_ip"),
            "hostname": row.get("hostname"),
            "mac_address": row.get("mac_address"),
            "vendor": row.get("vendor"),
            "os": row.get("os") or row.get("platform"),
            "device_type": row.get("device_type") or "Endpoint Agent",
            "agent": row,
            "ports": _normalise_ports(row.get("ports") or row.get("running_services") or []),
            "services": _normalise_services(row.get("services") or row.get("running_services") or []),
        }
        if asset.get("ip") or asset.get("hostname"):
            assets.append(asset)
    return assets


def _normalise_ports(values) -> List[Dict]:
    ports = []
    if not isinstance(values, list):
        return ports
    for item in values:
        if isinstance(item, dict):
            port = item.get("port")
            if port:
                ports.append({
                    "port": str(port),
                    "protocol": item.get("protocol", "tcp"),
                    "service": item.get("service") or item.get("name"),
                })
        elif isinstance(item, str) and ":" in item:
            name, _, port = item.partition(":")
            if port.strip().isdigit():
                ports.append({"port": port.strip(), "protocol": "tcp", "service": name.strip()})
    return ports


def _normalise_services(values) -> List[str]:
    services = []
    if not isinstance(values, list):
        return services
    for item in values:
        if isinstance(item, dict):
            value = item.get("service") or item.get("name")
        else:
            value = str(item).split(":", 1)[0]
        if value and value not in services:
            services.append(value)
    return services
