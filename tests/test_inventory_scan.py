from pathlib import Path

from scanning.inventory_scan import (
    _parse_arp_scan,
    classify_device,
    enrich_inventory,
)
from scanning.agent_import import import_agent_assets


def test_parse_arp_scan_extracts_mac_vendor():
    output = """
10.0.2.5\t08:00:27:aa:bb:cc\tPCS Systemtechnik GmbH
Interface: eth0
"""

    hosts = _parse_arp_scan(output)

    assert hosts == [
        {
            "ip": "10.0.2.5",
            "mac_address": "08:00:27:aa:bb:cc",
            "vendor": "PCS Systemtechnik GmbH",
            "source": "arp-scan",
            "discovery_method": "arp-scan",
            "ports": [],
            "services": [],
        }
    ]


def test_classify_device_uses_ports_and_snmp_text():
    assert classify_device({
        "ports": [{"port": "445"}],
        "services": ["microsoft-ds"],
        "os": "Microsoft Windows",
    }) == "Windows Workstation"

    assert classify_device({
        "ports": [{"port": "3306"}],
        "services": ["mysql"],
    }) == "Database Server"

    assert classify_device({
        "ports": [{"port": "161"}],
        "services": ["snmp"],
        "snmp": {"sysDescr": "HP LaserJet printer"},
    }) == "Printer"


def test_enrich_inventory_persists_sqlite_and_inventory_csv(tmp_path, monkeypatch):
    monkeypatch.setattr("scanning.inventory_scan.discover_hosts", lambda targets, out_dir: [
        {
            "ip": "10.0.2.5",
            "mac_address": "08:00:27:aa:bb:cc",
            "vendor": "PCS Systemtechnik GmbH",
            "source": "arp-scan",
            "discovery_method": "arp-scan",
            "ports": [],
            "services": [],
        }
    ])
    monkeypatch.setattr("scanning.inventory_scan.snmp_probe", lambda ip: {})

    assets = enrich_inventory(
        [
            {
                "ip": "10.0.2.5",
                "source": "nmap",
                "ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
                "services": ["ssh"],
                "os": "Linux",
            }
        ],
        ["10.0.2.0/24"],
        tmp_path,
        snmp=True,
    )

    assert assets[0]["mac_address"] == "08:00:27:aa:bb:cc"
    assert assets[0]["device_type"] == "Linux Server"
    assert assets[0]["first_seen"]
    assert assets[0]["last_seen"]
    assert (tmp_path / "inventory_assets.sqlite").exists()
    assert (tmp_path / "inventory_assets.csv").exists()
    assert "MAC Address" in (tmp_path / "inventory_assets.csv").read_text(encoding="utf-8")


def test_import_agent_assets_normalises_endpoint_json(tmp_path):
    path = tmp_path / "agent.json"
    path.write_text(
        """
{
  "hostname": "laptop-1",
  "primary_ip": "10.0.2.20",
  "platform": "Linux",
  "running_services": ["ssh:22", {"name": "nginx", "port": 80}]
}
""",
        encoding="utf-8",
    )

    assets = import_agent_assets(path)

    assert assets[0]["source"] == "inventa-agent"
    assert assets[0]["ip"] == "10.0.2.20"
    assert assets[0]["hostname"] == "laptop-1"
    assert {"port": "22", "protocol": "tcp", "service": "ssh"} in assets[0]["ports"]
    assert "nginx" in assets[0]["services"]
