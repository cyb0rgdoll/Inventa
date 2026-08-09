"""
Active Scanning Module
Nmap-based host and port discovery with configurable scan profiles.

When vulscan=True or vulners=True, the corresponding NSE scripts are appended
to the nmap command so that version-detected services are cross-referenced
against vulnerability databases during the scan itself.
"""

import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Optional

from core.targets import validate_targets


SCAN_PROFILES = {
    "low": {
        "timing": "T2",
        "port_args": ["-p", "21,22,23,25,53,80,110,143,443,445,3389,8080,8443"],
        "extra": [],
    },
    "medium": {
        "timing": "T3",
        "port_args": ["-p", "1-1024"],
        "extra": ["-sV"],
    },
    "high": {
        "timing": "T4",
        "port_args": ["--top-ports", "2000"],
        "extra": ["-sV", "-O"],
    },
}

VULSCAN_SCRIPT = "vulscan/vulscan.nse"
VULSCAN_DB_DEFAULT = "cve.csv"
VULNERS_SCRIPT = "vulners"

# Built-in NSE scripts (no installation required - come with nmap)
BUILTIN_NSE_SCRIPTS = {
    "service": [
        "smb-os-discovery",           # Windows/SMB enumeration
        "smb-enum-shares",            # SMB share enumeration
        "smb-enum-users",             # SMB user enumeration
        "ssh-hostkey",                # SSH key fingerprinting
        "ldap-search",                # LDAP enumeration
        "ssl-enum-ciphers",           # SSL/TLS cipher analysis
    ],
    "web": [
        "http-title",                 # HTTP title grabbing
        "http-headers",               # Security headers analysis
        "http-robots.txt",            # Robots.txt discovery
        "http-server-header",         # Web server detection
    ],
    "general": [
        "broadcast-dns-service-discovery",  # mDNS/LLMNR
        "snmp-sysdescr",              # SNMP system info
        "netbios-info",               # NetBIOS enumeration
    ]
}

_VULSCAN_PATHS = [
    Path("/usr/local/share/nmap/scripts/vulscan/vulscan.nse"),
    Path("/usr/share/nmap/scripts/vulscan/vulscan.nse"),
]
_VULNERS_PATHS = [
    Path("/usr/local/share/nmap/scripts/vulners.nse"),
    Path("/usr/share/nmap/scripts/vulners.nse"),
]


def _vulscan_available() -> bool:
    return any(p.exists() for p in _VULSCAN_PATHS)


def _vulners_available() -> bool:
    return any(p.exists() for p in _VULNERS_PATHS)


def _get_available_scripts() -> List[str]:
    """Return list of available NSE scripts that come with nmap."""
    available = []
    for category_scripts in BUILTIN_NSE_SCRIPTS.values():
        for script in category_scripts:
            # Check if script exists in nmap script dir
            nmap_script = Path(f"/usr/share/nmap/scripts/{script}.nse")
            if nmap_script.exists():
                available.append(script)
    return available


def active_scan(
    targets: List[str],
    profile: str,
    out_dir: Path,
    vulscan: bool = False,
    vulscan_db: str = VULSCAN_DB_DEFAULT,
    vulners: bool = False,
    use_nse: bool = True,
    nse_categories: Optional[List[str]] = None,
) -> List[Dict]:
    # Reject anything that is not a plain IP/CIDR/hostname before it can reach
    # nmap as an argument (CWE-88, argument injection).
    targets = validate_targets(targets)

    assets: List[Dict] = []
    profile_config = SCAN_PROFILES.get(profile, SCAN_PROFILES["low"])

    nmap_output = (out_dir / "nmap_scan.xml").resolve()

    extra = list(profile_config["extra"])
    script_names = []
    script_args = []

    # Add NSE scripts for better enumeration
    if use_nse and nse_categories is None:
        nse_categories = ["service", "web", "general"]

    if use_nse and nse_categories:
        for category in nse_categories:
            if category in BUILTIN_NSE_SCRIPTS:
                script_names.extend(BUILTIN_NSE_SCRIPTS[category])
        available_scripts = set(_get_available_scripts())
        missing_scripts = sorted(set(script_names) - available_scripts)
        script_names = [script for script in script_names if script in available_scripts]
        if missing_scripts:
            print(f"  [!] Skipping unavailable NSE script(s): {', '.join(missing_scripts)}")

    if vulscan:
        if not _vulscan_available():
            print("  [!] Vulscan NSE script not found — skipping vulscan")
            print("  [i] Install: git clone https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan")
            vulscan = False
        else:
            if "-sV" not in extra:
                extra.append("-sV")
            script_names.append(VULSCAN_SCRIPT)
            script_args.extend([f"vulscandb={vulscan_db}", "vulscanoutput=details"])
            print(f"  [+] Vulscan enabled (db: {vulscan_db})")

    if vulners:
        if not _vulners_available():
            print("  [!] Vulners NSE script not found — skipping vulners")
            print("  [i] Install: https://github.com/vulnersCom/nmap-vulners")
            vulners = False
        else:
            if "-sV" not in extra:
                extra.append("-sV")
            script_names.append(VULNERS_SCRIPT)
            print("  [+] Vulners enabled")

    if script_names:
        extra.append(f"--script={','.join(script_names)}")
    if script_args:
        extra.extend(["--script-args", ",".join(script_args)])

    cmd = [
        "nmap",
        f"-{profile_config['timing']}",
        *profile_config["port_args"],
        "-oX",
        str(nmap_output),
        "--open",
        *extra,
        "--",  # end of options: everything after is a target, never a flag
        *targets,
    ]

    print(f"[*] Running: {' '.join(cmd)}")
    print(f"[*] Output: {nmap_output}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )

        if result.returncode != 0:
            print(f"[!] Nmap returned non-zero exit code: {result.returncode}")
            print(f"[!] stderr: {result.stderr}")

        if nmap_output.exists():
            assets = parse_nmap_xml(nmap_output)
        else:
            print(f"[!] Nmap output file not found: {nmap_output}")

    except subprocess.TimeoutExpired:
        print("[!] Nmap scan timed out after 10 minutes")
    except Exception as e:
        print(f"[!] Nmap scan failed: {e}")

    return assets


def parse_nmap_xml(xml_file: Path) -> List[Dict]:
    """
    Parse Nmap XML output into asset dictionaries.
    Includes vulscan and vulners NSE script output when present.
    """
    assets: List[Dict] = []

    try:
        for event, elem in ET.iterparse(str(xml_file), events=("end",)):
            if elem.tag != "host":
                continue

            status = elem.find("status")
            if status is not None and status.get("state") != "up":
                elem.clear()
                continue

            asset = {
                "source": "nmap",
                "ports": [],
                "services": [],
                "os": None,
                "hostname": None,
            }

            addr = elem.find("address")
            if addr is not None:
                asset["ip"] = addr.get("addr")

            hostnames = elem.find("hostnames")
            if hostnames is not None:
                hostname = hostnames.find("hostname")
                if hostname is not None:
                    asset["hostname"] = hostname.get("name")

            ports_elem = elem.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        port_num = port.get("portid")
                        protocol = port.get("protocol")

                        service_elem = port.find("service")
                        service_name = None
                        service_version = None

                        if service_elem is not None:
                            service_name = service_elem.get("name")
                            conf = int(service_elem.get("conf", "100"))
                            product = service_elem.get("product", "") if conf > 30 else ""
                            version = service_elem.get("version", "")
                            service_version = f"{product} {version}".strip() or None

                        port_entry = {
                            "port": port_num,
                            "protocol": protocol,
                            "service": service_name,
                            "version": service_version,
                        }

                        vulscan_results = _parse_vulscan_scripts(port)
                        if vulscan_results:
                            port_entry["vulscan"] = vulscan_results
                        vulners_results = _parse_vulners_scripts(port)
                        if vulners_results:
                            port_entry["vulners"] = vulners_results

                        asset["ports"].append(port_entry)

                        if service_name and service_name not in asset["services"]:
                            asset["services"].append(service_name)

            os_elem = elem.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    asset["os"] = osmatch.get("name")

            _merge_script_vulns(asset, "vulscan")
            _merge_script_vulns(asset, "vulners")

            if "ip" in asset and asset["ports"]:
                assets.append(asset)

            elem.clear()

    except ET.ParseError as e:
        print(f"[!] Failed to parse Nmap XML: {e}")
    except Exception as e:
        print(f"[!] Error processing Nmap results: {e}")

    return assets


_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)
_VULSCAN_ENTRY_RE = re.compile(
    r"\[(\d+)\]\s+(.*?)(?=\s*\[\d+\]\s+|$)",
)


def _parse_vulscan_scripts(port_elem) -> List[Dict]:
    results = []
    for script in port_elem.findall("script"):
        if script.get("id") != "vulscan":
            continue

        output = script.get("output", "")
        if not output:
            continue

        for match in _VULSCAN_ENTRY_RE.finditer(output):
            vuln_id = match.group(1)
            title = match.group(2).strip()
            if not title or title.startswith("No "):
                continue

            cve_match = _CVE_RE.search(title)
            results.append({
                "id": vuln_id,
                "title": title[:200],
                "cve_id": cve_match.group(1).upper() if cve_match else None,
                "source": "vulscan",
            })

    return results


def _parse_vulners_scripts(port_elem) -> List[Dict]:
    results = []
    for script in port_elem.findall("script"):
        if script.get("id") != "vulners":
            continue

        for cpe_table in script.findall("table"):
            cpe = cpe_table.get("key")
            for vuln_table in cpe_table.findall("table"):
                vuln = {
                    "source": "vulners",
                    "cpe": cpe,
                }
                for elem in vuln_table.findall("elem"):
                    key = elem.get("key")
                    value = (elem.text or "").strip()
                    if key == "id":
                        vuln["cve_id"] = value
                    elif key == "cvss":
                        try:
                            vuln["cvss"] = float(value)
                        except ValueError:
                            vuln["cvss"] = None
                    elif key == "type":
                        vuln["bulletin_type"] = value
                    elif key == "is_exploit":
                        vuln["exploit_available"] = value.lower() == "true"

                cve_id = vuln.get("cve_id")
                if not cve_id:
                    continue

                vuln["id"] = cve_id
                vuln["title"] = cve_id
                results.append(vuln)

    return results


def _merge_script_vulns(asset: Dict, field_name: str):
    seen_cves = set()
    for port_entry in asset.get("ports", []):
        for vs in port_entry.get(field_name, []):
            cve_id = vs.get("cve_id")
            if not cve_id or cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            if "vulnerabilities" not in asset:
                asset["vulnerabilities"] = []
            asset["vulnerabilities"].append({
                "cve_id": cve_id,
                "summary": vs.get("title", ""),
                "cvss": vs.get("cvss"),
                "severity": vs.get("severity"),
                "published": None,
                "source": field_name,
                "port": port_entry.get("port"),
            })
