"""
Inventory discovery and enrichment.

Adds Lansweeper-inspired asset inventory fields on top of active nmap
results: ARP/MAC discovery, MAC vendor lookup, SNMP metadata, device
classification, and SQLite persistence.
"""

from __future__ import annotations

import csv
import ipaddress
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from core.targets import validate_targets


DEFAULT_SNMP_COMMUNITIES = ("public",)
COMMON_SNMP_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
}

VENDOR_HINTS = {
    "apple": "Apple",
    "cisco": "Cisco",
    "dell": "Dell",
    "hewlett": "HP",
    "hp": "HP",
    "huawei": "Huawei",
    "intel": "Intel",
    "juniper": "Juniper",
    "lenovo": "Lenovo",
    "microsoft": "Microsoft",
    "netgear": "Netgear",
    "raspberry": "Raspberry Pi",
    "samsung": "Samsung",
    "tp-link": "TP-Link",
    "ubiquiti": "Ubiquiti",
    "vmware": "VMware",
    "xerox": "Xerox",
    "zebra": "Zebra",
}


def enrich_inventory(
    assets: List[Dict],
    targets: Sequence[str],
    out_dir: Path,
    *,
    snmp: bool = True,
    passive: bool = False,
    ssh_deep: bool = False,
    db_path: Optional[Path] = None,
) -> List[Dict]:
    """
    Enrich discovered assets and add hosts found through inventory probes.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now().isoformat(timespec="seconds")
    merged = _merge_assets_by_ip(assets)

    discovered = discover_hosts(targets, out_dir)
    for host in discovered:
        ip = host.get("ip")
        if not ip:
            continue
        asset = merged.setdefault(ip, {"ip": ip, "ports": [], "services": []})
        _merge_asset(asset, host)

    if passive:
        for host in passive_neighbors():
            ip = host.get("ip")
            if not ip:
                continue
            asset = merged.setdefault(ip, {"ip": ip, "ports": [], "services": []})
            _merge_asset(asset, host)

    enriched = []
    for ip, asset in sorted(merged.items(), key=lambda item: _ip_sort_key(item[0])):
        asset.setdefault("ip", ip)
        asset.setdefault("ports", [])
        asset.setdefault("services", [])
        asset.setdefault("source", "inventory")
        asset["inventory_enabled"] = True
        asset["last_seen"] = now
        asset["discovery_methods"] = _discovery_methods(asset)

        if not asset.get("hostname"):
            asset["hostname"] = _reverse_dns(ip)

        if snmp and _should_try_snmp(asset):
            snmp_data = snmp_probe(ip)
            if snmp_data:
                asset["snmp"] = snmp_data
                if snmp_data.get("sysName") and not asset.get("hostname"):
                    asset["hostname"] = snmp_data["sysName"]
                vendor = _vendor_from_text(" ".join(str(v) for v in snmp_data.values()))
                if vendor and not asset.get("vendor"):
                    asset["vendor"] = vendor

        if ssh_deep and _should_try_ssh(asset):
            deep = ssh_deep_scan(ip)
            if deep:
                asset["ssh_deep_scan"] = deep
                if deep.get("hostname") and not asset.get("hostname"):
                    asset["hostname"] = deep["hostname"]
                if deep.get("os_release") and not asset.get("os"):
                    asset["os"] = deep["os_release"]

        asset["device_type"] = classify_device(asset)
        asset["asset_type"] = asset.get("asset_type") or asset["device_type"]
        enriched.append(asset)

    if db_path is None:
        db_path = out_dir / "inventory_assets.sqlite"
    persist_inventory(enriched, db_path)

    write_inventory_reports(enriched, out_dir)
    return enriched


def discover_hosts(targets: Sequence[str], out_dir: Path) -> List[Dict]:
    hosts: Dict[str, Dict] = {}
    _merge_host_lists(hosts, _run_arp_scan(targets, out_dir))
    _merge_host_lists(hosts, _run_nmap_ping(targets, out_dir))
    return list(hosts.values())


def _run_arp_scan(targets: Sequence[str], out_dir: Path) -> List[Dict]:
    if not shutil.which("arp-scan"):
        return []

    results: List[Dict] = []
    # _cidr_targets already discards anything that is not a valid CIDR, so each
    # target here is safe to pass to arp-scan.
    for target in _cidr_targets(targets):
        output_path = out_dir / f"arp_scan_{_safe_name(target)}.txt"
        cmd = ["arp-scan", "--plain", "--ignoredups", "--", target]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output_path.write_text(result.stdout + result.stderr, encoding="utf-8", errors="ignore")
        except (subprocess.SubprocessError, OSError) as exc:
            print(f"[!] arp-scan failed for {target}: {exc}", file=sys.stderr)
            continue
        results.extend(_parse_arp_scan(result.stdout))
    return results


def _run_nmap_ping(targets: Sequence[str], out_dir: Path) -> List[Dict]:
    if not shutil.which("nmap"):
        return []

    # Validate before spreading into the nmap argv (CWE-88, argument injection),
    # and add "--" so a target can never be parsed as a flag.
    try:
        safe_targets = validate_targets(targets)
    except ValueError as exc:
        print(f"[!] Skipping host discovery — invalid target: {exc}", file=sys.stderr)
        return []

    output_path = out_dir / "inventory_host_discovery.xml"
    cmd = ["nmap", "-sn", "-oX", str(output_path), "--", *safe_targets]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    except (subprocess.SubprocessError, OSError) as exc:
        print(f"[!] nmap host discovery failed: {exc}", file=sys.stderr)
        return []
    if not output_path.exists():
        return []
    return _parse_nmap_ping_xml(output_path)


def _parse_arp_scan(output: str) -> List[Dict]:
    hosts = []
    for line in output.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        ip, mac = parts[0], parts[1]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not _looks_like_mac(mac):
            continue
        vendor = parts[2].strip() if len(parts) > 2 else ""
        hosts.append({
            "ip": ip,
            "mac_address": mac.lower(),
            "vendor": vendor,
            "source": "arp-scan",
            "discovery_method": "arp-scan",
            "ports": [],
            "services": [],
        })
    return hosts


def _parse_nmap_ping_xml(path: Path) -> List[Dict]:
    hosts = []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return hosts

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        item = {
            "source": "nmap-ping",
            "discovery_method": "nmap -sn",
            "ports": [],
            "services": [],
        }
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type in {"ipv4", "ipv6"}:
                item["ip"] = addr.get("addr")
            elif addr_type == "mac":
                item["mac_address"] = (addr.get("addr") or "").lower()
                if addr.get("vendor"):
                    item["vendor"] = addr.get("vendor")
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hostname = hostnames.find("hostname")
            if hostname is not None:
                item["hostname"] = hostname.get("name")
        if item.get("ip"):
            hosts.append(item)
    return hosts


def passive_neighbors() -> List[Dict]:
    hosts: Dict[str, Dict] = {}
    for host in _parse_ip_neigh(_run_text(["ip", "neigh"])):
        hosts[host["ip"]] = host
    for host in _parse_arp_table(_run_text(["arp", "-an"])):
        hosts.setdefault(host["ip"], {}).update(host)
    return list(hosts.values())


def _parse_ip_neigh(output: str) -> List[Dict]:
    hosts = []
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        mac = ""
        if "lladdr" in parts:
            idx = parts.index("lladdr")
            if idx + 1 < len(parts) and _looks_like_mac(parts[idx + 1]):
                mac = parts[idx + 1].lower()
        state = parts[-1] if parts else ""
        hosts.append({
            "ip": ip,
            "mac_address": mac,
            "neighbor_state": state,
            "source": "passive-neighbor-cache",
            "discovery_method": "ip neigh",
            "ports": [],
            "services": [],
        })
    return hosts


def _parse_arp_table(output: str) -> List[Dict]:
    hosts = []
    for line in output.splitlines():
        ip_match = re.search(r"\(([^)]+)\)", line)
        mac_match = re.search(r"(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", line)
        if not ip_match:
            continue
        ip = ip_match.group(1)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        hosts.append({
            "ip": ip,
            "mac_address": mac_match.group(1).lower() if mac_match else "",
            "source": "passive-arp-cache",
            "discovery_method": "arp -an",
            "ports": [],
            "services": [],
        })
    return hosts


def snmp_probe(ip: str, communities: Sequence[str] = DEFAULT_SNMP_COMMUNITIES) -> Dict:
    if not shutil.which("snmpwalk"):
        return {}

    data = {}
    for community in communities:
        for label, oid in COMMON_SNMP_OIDS.items():
            value = _snmp_get(ip, community, oid)
            if value:
                data[label] = value
        if data:
            data["community"] = community
            break

    if data:
        data["interfaces"] = _snmp_interfaces(ip, data.get("community", communities[0]))
        serial = _serial_from_text(" ".join(str(v) for v in data.values()))
        if serial:
            data["serial"] = serial
        model = _model_from_text(data.get("sysDescr", ""))
        if model:
            data["model"] = model
    return data


def _snmp_get(ip: str, community: str, oid: str) -> str:
    output = _run_text(["snmpwalk", "-v2c", "-c", community, "-Oqv", "-t", "1", "-r", "1", ip, oid], timeout=8)
    value = output.strip().strip('"')
    if not value or "Timeout" in value or "No Such" in value:
        return ""
    return value


def _snmp_interfaces(ip: str, community: str) -> List[str]:
    output = _run_text(["snmpwalk", "-v2c", "-c", community, "-Oqv", "-t", "1", "-r", "1", ip, "1.3.6.1.2.1.2.2.1.2"], timeout=12)
    interfaces = []
    for line in output.splitlines():
        value = line.strip().strip('"')
        if value and "Timeout" not in value and "No Such" not in value:
            interfaces.append(value)
    return interfaces[:30]


def classify_device(asset: Dict) -> str:
    ports = {str(p.get("port")) for p in asset.get("ports", []) if p.get("port") is not None}
    services = {str(s).lower() for s in asset.get("services", [])}
    service_text = " ".join(services)
    versions = " ".join(str(p.get("version", "")) for p in asset.get("ports", []))
    hostname = str(asset.get("hostname") or "").lower()
    os_info = str(asset.get("os") or "").lower()
    vendor = str(asset.get("vendor") or "").lower()
    snmp_text = " ".join(str(v).lower() for v in asset.get("snmp", {}).values())
    all_text = " ".join([service_text, versions.lower(), hostname, os_info, vendor, snmp_text])

    if any(port in ports for port in ("3306", "5432", "1433", "1521", "27017", "6379")):
        return "Database Server"
    if any(port in ports for port in ("80", "443", "8080", "8443")) or {"http", "https"} & services:
        if any(token in all_text for token in ("camera", "webcam", "dvr", "nvr", "hikvision", "axis")):
            return "Camera"
        return "Web Server"
    if "445" in ports or "microsoft-ds" in services or "smb" in service_text:
        if "windows" in all_text or "microsoft" in all_text:
            return "Windows Workstation"
        return "File Server"
    if "22" in ports or "ssh" in services:
        if any(token in all_text for token in ("linux", "ubuntu", "debian", "openssh")):
            return "Linux Server"
    if "161" in ports or asset.get("snmp"):
        if any(token in all_text for token in ("printer", "laserjet", "officejet", "xerox", "zebra")):
            return "Printer"
        if any(token in all_text for token in ("switch", "cisco", "juniper", "netgear", "procurve")):
            return "Switch"
        if any(token in all_text for token in ("router", "gateway", "ubiquiti", "mikrotik")):
            return "Router"
        return "Network Device"
    if any(token in all_text for token in ("nas", "synology", "qnap", "truenas")):
        return "NAS"
    if "windows" in all_text:
        return "Windows Workstation"
    if any(token in all_text for token in ("linux", "ubuntu", "debian", "centos", "red hat")):
        return "Linux Server"
    if any(token in all_text for token in ("printer", "laserjet", "officejet", "xerox")):
        return "Printer"
    if any(token in all_text for token in ("camera", "dvr", "nvr")):
        return "Camera"
    return "Unknown Device"


def ssh_deep_scan(ip: str) -> Dict:
    """
    Optional Linux/macOS deep scan over SSH.

    Uses key-based SSH by default. Configure with:
    INVENTA_SSH_USER, INVENTA_SSH_KEY, INVENTA_SSH_PORT.
    """
    if not shutil.which("ssh"):
        return {}
    user = _env("INVENTA_SSH_USER")
    if not user:
        return {}
    port = _env("INVENTA_SSH_PORT", "22")
    key = _env("INVENTA_SSH_KEY")
    base = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=5",
        "-p", port,
    ]
    if key:
        base.extend(["-i", key])
    destination = f"{user}@{ip}"
    commands = {
        "hostname": "hostname 2>/dev/null",
        "os_release": "cat /etc/os-release 2>/dev/null | head -20",
        "kernel": "uname -a 2>/dev/null",
        "users": "cut -d: -f1 /etc/passwd 2>/dev/null | head -50",
        "services": "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -50",
        "cpu": "lscpu 2>/dev/null | head -20",
        "memory": "free -h 2>/dev/null",
        "disk": "df -h 2>/dev/null",
        "docker": "docker ps --format '{{.Names}} {{.Image}} {{.Status}}' 2>/dev/null | head -50",
        "packages": "command -v dpkg >/dev/null && dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null | head -100 || true",
    }
    data = {}
    for key_name, command in commands.items():
        output = _run_text([*base, destination, command], timeout=15).strip()
        if output:
            data[key_name] = output
    return data


def persist_inventory(assets: List[Dict], db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS inventory_assets (
            ip TEXT PRIMARY KEY,
            mac_address TEXT,
            vendor TEXT,
            hostname TEXT,
            device_type TEXT,
            os TEXT,
            first_seen TEXT,
            last_seen TEXT,
            discovery_methods TEXT,
            open_ports TEXT,
            services TEXT,
            snmp_sysname TEXT,
            snmp_sysdescr TEXT
        )
    """)
    now = datetime.now().isoformat(timespec="seconds")
    for asset in assets:
        ip = asset.get("ip")
        if not ip:
            continue
        cur.execute("SELECT first_seen FROM inventory_assets WHERE ip = ?", (ip,))
        row = cur.fetchone()
        first_seen = row[0] if row else asset.get("first_seen") or now
        methods = ", ".join(asset.get("discovery_methods", []))
        ports = ", ".join(str(p.get("port")) for p in asset.get("ports", []) if p.get("port") is not None)
        services = ", ".join(str(s) for s in asset.get("services", []))
        snmp = asset.get("snmp", {})
        cur.execute("""
            INSERT INTO inventory_assets (
                ip, mac_address, vendor, hostname, device_type, os, first_seen, last_seen,
                discovery_methods, open_ports, services, snmp_sysname, snmp_sysdescr
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                mac_address = excluded.mac_address,
                vendor = excluded.vendor,
                hostname = excluded.hostname,
                device_type = excluded.device_type,
                os = excluded.os,
                last_seen = excluded.last_seen,
                discovery_methods = excluded.discovery_methods,
                open_ports = excluded.open_ports,
                services = excluded.services,
                snmp_sysname = excluded.snmp_sysname,
                snmp_sysdescr = excluded.snmp_sysdescr
        """, (
            ip, asset.get("mac_address"), asset.get("vendor"), asset.get("hostname"),
            asset.get("device_type"), asset.get("os"), first_seen, asset.get("last_seen") or now,
            methods, ports, services, snmp.get("sysName"), snmp.get("sysDescr"),
        ))
        asset["first_seen"] = first_seen
    conn.commit()
    conn.close()


def write_inventory_reports(assets: List[Dict], out_dir: Path) -> None:
    path = out_dir / "inventory_assets.csv"
    fields = [
        "IP", "MAC Address", "Vendor", "Hostname", "Device Type", "OS",
        "First Seen", "Last Seen", "Discovery Methods", "Open Ports",
        "Services", "SNMP Name", "SNMP Description",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for asset in assets:
            snmp = asset.get("snmp", {})
            writer.writerow({
                "IP": asset.get("ip", ""),
                "MAC Address": asset.get("mac_address", ""),
                "Vendor": asset.get("vendor", ""),
                "Hostname": asset.get("hostname", ""),
                "Device Type": asset.get("device_type", ""),
                "OS": asset.get("os", ""),
                "First Seen": asset.get("first_seen", ""),
                "Last Seen": asset.get("last_seen", ""),
                "Discovery Methods": ", ".join(asset.get("discovery_methods", [])),
                "Open Ports": ", ".join(str(p.get("port")) for p in asset.get("ports", []) if p.get("port") is not None),
                "Services": ", ".join(str(s) for s in asset.get("services", [])),
                "SNMP Name": snmp.get("sysName", ""),
                "SNMP Description": snmp.get("sysDescr", ""),
            })


def _merge_assets_by_ip(assets: Iterable[Dict]) -> Dict[str, Dict]:
    merged: Dict[str, Dict] = {}
    for asset in assets:
        ip = asset.get("ip") or asset.get("public_ip")
        if not ip:
            continue
        if ip not in merged:
            merged[ip] = dict(asset)
        else:
            _merge_asset(merged[ip], asset)
    return merged


def _merge_asset(base: Dict, incoming: Dict) -> Dict:
    for key, value in incoming.items():
        if value in (None, "", [], {}):
            continue
        if key in {"ports", "services", "discovery_methods"}:
            base[key] = _merge_unique(base.get(key, []), value)
        elif key == "source":
            sources = base.get("sources", [])
            if base.get("source"):
                sources.append(base["source"])
            sources.append(value)
            base["sources"] = _merge_unique([], sources)
            base.setdefault("source", value)
        elif key not in base or base.get(key) in (None, "", [], {}):
            base[key] = value
    return base


def _merge_host_lists(hosts: Dict[str, Dict], incoming: Iterable[Dict]) -> None:
    for host in incoming:
        ip = host.get("ip")
        if not ip:
            continue
        if ip not in hosts:
            hosts[ip] = host
        else:
            _merge_asset(hosts[ip], host)


def _merge_unique(existing: Sequence, incoming: Sequence) -> List:
    values = []
    seen = set()
    for item in [*(existing or []), *(incoming or [])]:
        marker = repr(item)
        if marker in seen:
            continue
        seen.add(marker)
        values.append(item)
    return values


def _discovery_methods(asset: Dict) -> List[str]:
    methods = []
    for field in ("discovery_methods", "discovery_method", "source"):
        value = asset.get(field)
        if isinstance(value, list):
            methods.extend(str(v) for v in value if v)
        elif value:
            methods.append(str(value))
    methods.extend(str(v) for v in asset.get("sources", []) if v)
    if asset.get("ports"):
        methods.append("nmap service scan")
    if asset.get("snmp"):
        methods.append("snmp")
    return _merge_unique([], methods)


def _should_try_snmp(asset: Dict) -> bool:
    ports = {str(p.get("port")) for p in asset.get("ports", []) if p.get("port") is not None}
    return not ports or "161" in ports or asset.get("device_type") in {"Router", "Switch", "Printer", "Network Device"}


def _should_try_ssh(asset: Dict) -> bool:
    ports = {str(p.get("port")) for p in asset.get("ports", []) if p.get("port") is not None}
    services = {str(service).lower() for service in asset.get("services", [])}
    return "22" in ports or "ssh" in services


def _env(name: str, default: str = "") -> str:
    import os
    return os.environ.get(name, default).strip()


def _cidr_targets(targets: Sequence[str]) -> List[str]:
    cidrs = []
    for target in targets:
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            continue
        cidrs.append(str(target))
    return cidrs


def _run_text(cmd: List[str], timeout: int = 20) -> str:
    if not cmd or not shutil.which(cmd[0]):
        return ""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return ""
    return (result.stdout or "") + (result.stderr or "")


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _looks_like_mac(value: str) -> bool:
    return bool(re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value or ""))


def _vendor_from_text(text: str) -> str:
    lowered = text.lower()
    for token, vendor in VENDOR_HINTS.items():
        if token in lowered:
            return vendor
    return ""


def _serial_from_text(text: str) -> str:
    match = re.search(r"(?:serial|sn)[:\s#-]+([A-Za-z0-9._-]{4,})", text, re.IGNORECASE)
    return match.group(1) if match else ""


def _model_from_text(text: str) -> str:
    value = " ".join(text.split())
    if len(value) > 120:
        value = value[:120]
    return value


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value)).strip("_") or "target"


def _ip_sort_key(ip: str):
    try:
        return (0, ipaddress.ip_address(ip))
    except ValueError:
        return (1, ip)
