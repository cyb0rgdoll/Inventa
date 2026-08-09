from pathlib import Path

from modules.active_scan import parse_nmap_xml


def test_parse_nmap_xml_extracts_open_ports(tmp_path: Path):
    xml_file = tmp_path / "nmap.xml"
    xml_file.write_text(
        """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="router.local"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.11" addrtype="ipv4"/>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )

    assets = parse_nmap_xml(xml_file)

    assert assets == [
        {
            "source": "nmap",
            "ip": "192.168.1.10",
            "hostname": "router.local",
            "os": None,
            "services": ["http"],
            "ports": [
                {
                    "port": "80",
                    "protocol": "tcp",
                    "service": "http",
                    "version": "nginx 1.24.0",
                }
            ],
        }
    ]


def test_parse_nmap_xml_extracts_multiple_vulscan_entries(tmp_path: Path):
    xml_file = tmp_path / "vulscan.xml"
    xml_file.write_text(
        """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24.0"/>
        <script id="vulscan" output="[12345] CVE-2024-0001 first issue&#10;[67890] CVE-2024-0002 second issue"/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )

    assets = parse_nmap_xml(xml_file)

    assert assets[0]["ports"][0]["vulscan"] == [
        {
            "id": "12345",
            "title": "CVE-2024-0001 first issue",
            "cve_id": "CVE-2024-0001",
            "source": "vulscan",
        },
        {
            "id": "67890",
            "title": "CVE-2024-0002 second issue",
            "cve_id": "CVE-2024-0002",
            "source": "vulscan",
        },
    ]
    assert assets[0]["vulnerabilities"] == [
        {
            "cve_id": "CVE-2024-0001",
            "summary": "CVE-2024-0001 first issue",
            "cvss": None,
            "severity": None,
            "published": None,
            "source": "vulscan",
            "port": "443",
        },
        {
            "cve_id": "CVE-2024-0002",
            "summary": "CVE-2024-0002 second issue",
            "cvss": None,
            "severity": None,
            "published": None,
            "source": "vulscan",
            "port": "443",
        },
    ]


def test_parse_nmap_xml_extracts_vulners_entries(tmp_path: Path):
    xml_file = tmp_path / "vulners.xml"
    xml_file.write_text(
        """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="53">
        <state state="open"/>
        <service name="domain" product="ISC BIND DNS" version="9.8.2rc1"/>
        <script id="vulners">
          <table key="cpe:/a:isc:bind:9.8.2rc1">
            <table>
              <elem key="is_exploit">false</elem>
              <elem key="cvss">8.5</elem>
              <elem key="id">CVE-2012-1667</elem>
              <elem key="type">cve</elem>
            </table>
            <table>
              <elem key="is_exploit">true</elem>
              <elem key="cvss">7.8</elem>
              <elem key="id">CVE-2015-4620</elem>
              <elem key="type">exploit</elem>
            </table>
          </table>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )

    assets = parse_nmap_xml(xml_file)

    assert assets[0]["ports"][0]["vulners"] == [
        {
            "source": "vulners",
            "cpe": "cpe:/a:isc:bind:9.8.2rc1",
            "exploit_available": False,
            "cvss": 8.5,
            "cve_id": "CVE-2012-1667",
            "bulletin_type": "cve",
            "id": "CVE-2012-1667",
            "title": "CVE-2012-1667",
        },
        {
            "source": "vulners",
            "cpe": "cpe:/a:isc:bind:9.8.2rc1",
            "exploit_available": True,
            "cvss": 7.8,
            "cve_id": "CVE-2015-4620",
            "bulletin_type": "exploit",
            "id": "CVE-2015-4620",
            "title": "CVE-2015-4620",
        },
    ]
    assert assets[0]["vulnerabilities"] == [
        {
            "cve_id": "CVE-2012-1667",
            "summary": "CVE-2012-1667",
            "cvss": 8.5,
            "severity": None,
            "published": None,
            "source": "vulners",
            "port": "53",
        },
        {
            "cve_id": "CVE-2015-4620",
            "summary": "CVE-2015-4620",
            "cvss": 7.8,
            "severity": None,
            "published": None,
            "source": "vulners",
            "port": "53",
        },
    ]
