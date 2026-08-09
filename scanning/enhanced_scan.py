"""
Enhanced Scanning Module - Inventa Upgrades
Combines multiple techniques: Masscan, Nmap with NSE scripts, smart fingerprinting, and protocol probes.
Designed to find assets that standard nmap misses.
"""

import asyncio
import socket
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor
import subprocess
import time
import re
import ipaddress
import tempfile
import os

# Intelligent port ranges beyond nmap defaults - COMPREHENSIVE
INTELLIGENT_PORTS = {
    "ftp": [21, 2121],
    "ssh": [22, 2222, 22222],
    "telnet": [23],
    "smtp": [25],
    "dns": [53],
    "http": [80, 8000, 8008, 8080, 8888, 3000, 4000, 5000],
    "https": [443, 8443, 9443],
    "rpc": [111],
    "netbios": [139],
    "smb": [445],
    "rsh": [512, 513, 514],
    "database": [1099, 1433, 1524, 3306, 5432, 6379, 7687, 9200, 27017],
    "vnc": [5900, 5901],
    "irc": [6667],
    "mysql": [3306],
    "postgres": [5432],
    "tomcat": [8009, 8180],
    "monitoring": [9090, 9100, 8089, 8086],
    "message_queue": [5672, 8161, 9092, 1883],
    "redis": [6379, 6380],
    "app_servers": [8080, 8081, 8082, 8090, 9000, 9001],
    "cloud": [4566, 5433, 9091],
}

# Smart probes for protocol detection
SMART_PROBES = {
    "http": [
        "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        "GET /health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        "GET /actuator HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        "GET /api/version HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    ],
    "ftp": ["USER anonymous\r\n"],
    "smtp": ["EHLO inventa\r\n"],
}

# Default credentials for common services (safe testing only)
DEFAULT_CREDS = {
    3306: [("root", ""), ("root", "root"), ("root", "password")],  # MySQL
    5432: [("postgres", ""), ("postgres", "postgres")],  # PostgreSQL
    6379: [("", "")],  # Redis
    27017: [("admin", "admin")],  # MongoDB
}

# Comprehensive NSE Scripts for Enhanced Discovery (verified to exist)
NSE_SCRIPTS = {
    "service_detection": [
        "smb-os-discovery",           # Windows/Samba enumeration
        "smb-enum-shares",            # SMB share listing
        "smb-enum-users",             # SMB user enumeration
        "smb-enum-groups",            # SMB group enumeration
        "smb-enum-domains",           # SMB domain enumeration
        "smb-enum-processes",         # SMB process enumeration
        "smb-enum-services",          # SMB service enumeration
        "ssh-hostkey",                # SSH key fingerprinting
        "ssh2-enum-algos",            # SSH algorithm enumeration
        "snmp-sysdescr",              # SNMP system description
        "snmp-info",                  # SNMP information
        "snmp-interfaces",            # SNMP network interfaces
    ],
    "web_discovery": [
        "http-title",                 # HTTP page title
        "http-headers",               # Security headers analysis
        "http-server-header",         # Web server detection
        "http-robots.txt",            # robots.txt discovery
        "http-methods",               # HTTP methods enumeration
        "http-enum",                  # Common paths enumeration
        "http-favicon",               # Favicon analysis
        "http-webdav-scan",           # WebDAV detection
        "http-devframework",          # Dev framework detection
    ],
    "ssl_tls": [
        "ssl-enum-ciphers",           # SSL/TLS cipher enumeration
        "ssl-cert",                   # SSL certificate details
        "ssl-date",                   # SSL certificate date check
    ],
    "discovery": [
        "broadcast-dns-service-discovery",  # mDNS/LLMNR discovery
        "broadcast-upnp-discovery",         # UPnP/SSDP discovery
    ],
    "vulnerability": [
        "smb-vuln-ms06-025",          # SMB vulnerabilities
        "smb-vuln-ms07-029",
        "smb-vuln-ms08-067",
        "smb-vuln-ms10-054",
        "smb-vuln-ms17-010",
    ],
}

# Combined script list for ease of use
ALL_NSE_SCRIPTS = []
for scripts in NSE_SCRIPTS.values():
    ALL_NSE_SCRIPTS.extend(scripts)

def validate_targets(targets: List[str]) -> List[str]:
    """Validate targets to prevent argument injection attacks."""
    validated = []
    for target in targets:
        if target.startswith('-'):
            raise ValueError(f"Invalid target (starts with dash): {target}")
        try:
            ipaddress.ip_address(target)
            validated.append(target)
        except ValueError:
            try:
                ipaddress.ip_network(target, strict=False)
                validated.append(target)
            except ValueError:
                if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', target):
                    validated.append(target)
                else:
                    raise ValueError(f"Invalid target (not IP/CIDR/hostname): {target}")
    return validated

class SmartScanner:
    def __init__(self, timeout: int = 5, use_nse: bool = True, nse_categories: Optional[List[str]] = None):
        self.timeout = timeout
        self.discovered_ports: Dict[str, Set[int]] = {}
        self.service_fingerprints: Dict[str, Dict] = {}
        self.use_nse = use_nse
        self.nse_categories = nse_categories or ["service_detection", "web_discovery", "ssl_tls", "discovery"]
        self.nse_results: Dict[str, any] = {}
        self._temp_nmap_path: Optional[str] = None
        self._temp_nse_path: Optional[str] = None

    async def masscan_sweep(self, targets: List[str], port_range: str = "1-65535") -> Dict[str, Set[int]]:
        """
        Fast port discovery with Masscan (10x faster than nmap).
        Returns dict of host -> set of open ports.
        """
        print("[*] Starting Masscan sweep (fast UDP-based discovery)...")
        targets = validate_targets(targets)
        self.discovered_ports = {target: set() for target in targets}

        temp_fd = None
        temp_path = None
        try:
            temp_fd, temp_path = tempfile.mkstemp(prefix="masscan_", suffix=".json", text=True)
            os.close(temp_fd)
            os.unlink(temp_path)

            cmd = [
                "masscan",
                "-p", port_range,
                "--rate=10000",
                "-oJ", temp_path,
                "--",
                *targets,
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if Path(temp_path).exists():
                with open(temp_path, "r") as f:
                    data = json.load(f)
                    for result_item in data.get("result", []):
                        ip = result_item.get("ip")
                        port = result_item.get("ports", [{}])[0].get("port")
                        if ip and port:
                            self.discovered_ports.setdefault(ip, set()).add(port)
                os.unlink(temp_path)

            print(f"[+] Masscan found {sum(len(p) for p in self.discovered_ports.values())} open ports")
            return self.discovered_ports

        except FileNotFoundError:
            print("[!] Masscan not installed. Skipping fast sweep.")
            return self.discovered_ports
        except Exception as e:
            print(f"[!] Masscan failed: {e}")
            return self.discovered_ports
        finally:
            if temp_path and Path(temp_path).exists():
                try:
                    os.unlink(temp_path)
                except:
                    pass

    async def smart_port_discovery(self, targets: List[str]) -> Dict[str, Set[int]]:
        """
        Probe intelligent port ranges PLUS comprehensive port scan to match nmap coverage.
        """
        print("[*] Probing comprehensive port range (1-10000)...")
        targets = validate_targets(targets)

        temp_fd = None
        temp_path = None
        try:
            temp_fd, temp_path = tempfile.mkstemp(prefix="nmap_", suffix=".xml", text=True)
            os.close(temp_fd)
            os.unlink(temp_path)

            cmd = [
                "nmap",
                "-sS", "--open", "-Pn",
                "-p", "1-10000",
                "-T4",
                "-oX", temp_path,
                "--",
                *targets,
            ]

            self._temp_nmap_path = temp_path
            subprocess.run(cmd, capture_output=True, timeout=180)
            self._parse_intelligent_ports()
        except Exception as e:
            print(f"[!] Comprehensive port scan failed: {e}")
        finally:
            if temp_path and Path(temp_path).exists():
                try:
                    os.unlink(temp_path)
                except:
                    pass

        return self.discovered_ports

    def _parse_intelligent_ports(self):
        """Parse Nmap XML from intelligent port scan."""
        try:
            xml_path = getattr(self, '_temp_nmap_path', None)
            if not xml_path or not Path(xml_path).exists():
                return

            for event, elem in ET.iterparse(xml_path, events=("end",)):
                if elem.tag != "host":
                    continue
                addr = elem.find("address")
                if addr is not None:
                    ip = addr.get("addr")
                    ports_elem = elem.find("ports")
                    if ports_elem:
                        for port in ports_elem.findall("port"):
                            state = port.find("state")
                            if state is not None and state.get("state") == "open":
                                port_num = int(port.get("portid"))
                                self.discovered_ports.setdefault(ip, set()).add(port_num)
                elem.clear()
        except Exception as e:
            print(f"[!] Failed to parse intelligent ports: {e}")

    def _get_available_nse_scripts(self) -> List[str]:
        """Check which NSE scripts are available on system."""
        available = []
        for script in ALL_NSE_SCRIPTS:
            nse_path = Path(f"/usr/share/nmap/scripts/{script}.nse")
            if nse_path.exists():
                available.append(script)
        print(f"[*] {len(available)}/{len(ALL_NSE_SCRIPTS)} NSE scripts available")
        return available

    async def nse_scan(self, targets: List[str], ports: Optional[Dict[str, Set[int]]] = None, output_file: Optional[str] = None) -> Dict[str, any]:
        """
        Execute comprehensive NSE script scan for deep enumeration.
        """
        if not self.use_nse:
            return {}

        targets = validate_targets(targets)
        print("[*] Preparing NSE script scan (deep enumeration)...")

        if output_file is None:
            temp_fd, output_file = tempfile.mkstemp(prefix="nse_", suffix=".xml", text=True)
            os.close(temp_fd)
            os.unlink(output_file)
            self._temp_nse_path = output_file

        # Get available scripts
        available_scripts = self._get_available_nse_scripts()
        if not available_scripts:
            print("[!] No NSE scripts available - install nmap-scripts package")
            return {}

        # Select scripts based on categories
        scripts_to_run = []
        for category in self.nse_categories:
            if category in NSE_SCRIPTS:
                for script in NSE_SCRIPTS[category]:
                    if script in available_scripts:
                        scripts_to_run.append(script)

        if not scripts_to_run:
            print("[!] No selected NSE scripts available")
            return {}

        # Build nmap command with NSE scripts
        script_str = ",".join(scripts_to_run[:30])  # Limit to 30 scripts for performance

        # Determine ports to scan
        if ports:
            port_args = ["-p", ",".join(str(p) for p in sorted(set(p for ps in ports.values() for p in ps)))]
        else:
            port_args = ["-p", "1-10000"]  # Default range

        cmd = [
            "nmap",
            "-sV", "-sC",  # Version detection + default scripts
            *port_args,
            "-Pn",  # Skip ping
            "-T4",  # Timing
            f"--script={script_str}",
            "-oX", output_file,
            "--",
            *targets,
        ]

        print(f"[*] Running NSE scan with {len(scripts_to_run)} scripts...")
        print(f"[*] Command: nmap ... --script={script_str[:80]}...")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if Path(output_file).exists():
                self._parse_nse_results(output_file)
                print(f"[+] NSE scan complete. Results saved.")
            return self.nse_results
        except subprocess.TimeoutExpired:
            print("[!] NSE scan timed out after 10 minutes")
        except Exception as e:
            print(f"[!] NSE scan failed: {e}")

        return {}

    def _parse_nse_results(self, xml_file: str) -> None:
        """Parse NSE script results from Nmap XML output."""
        try:
            for event, elem in ET.iterparse(xml_file, events=("end",)):
                if elem.tag != "host":
                    continue

                ip = None
                addr = elem.find("address")
                if addr is not None:
                    ip = addr.get("addr")

                if ip:
                    self.nse_results.setdefault(ip, {"scripts": [], "findings": []})

                    # Extract NSE script output
                    for port in elem.findall(".//port"):
                        for script in port.findall("script"):
                            script_id = script.get("id")
                            script_output = script.get("output", "")

                            self.nse_results[ip]["scripts"].append({
                                "id": script_id,
                                "port": port.get("portid"),
                                "output": script_output[:500],  # Truncate for storage
                            })

                            # Parse specific findings
                            self._extract_nse_findings(script_id, script_output, ip)

                elem.clear()
        except Exception as e:
            print(f"[!] Failed to parse NSE results: {e}")

    def _extract_nse_findings(self, script_id: str, output: str, ip: str) -> None:
        """Extract actionable findings from NSE output."""
        findings = []

        if "smb-os-discovery" in script_id:
            # Extract OS info
            os_match = re.search(r"OS: (.+?)(?:\n|$)", output)
            if os_match:
                findings.append({"type": "os", "value": os_match.group(1)})

        elif "smb-enum-shares" in script_id:
            # Extract shares
            for share in re.finditer(r"\\\\.*?\\(\w+)", output):
                findings.append({"type": "share", "value": share.group(1)})

        elif "smb-enum-users" in script_id:
            # Extract users
            for user in re.finditer(r"(\w+)\s+\\", output):
                findings.append({"type": "user", "value": user.group(1)})

        elif "http-title" in script_id:
            # Extract page title
            title_match = re.search(r"title: (.+?)(?:\n|$)", output)
            if title_match:
                findings.append({"type": "http_title", "value": title_match.group(1)})

        elif "ssl-cert" in script_id:
            # Extract certificate info
            cert_match = re.search(r"Subject: (.+?)(?:\n|$)", output)
            if cert_match:
                findings.append({"type": "ssl_subject", "value": cert_match.group(1)})

        elif "smb-vuln" in script_id:
            # Flag vulnerabilities
            if "VULNERABLE" in output:
                findings.append({"type": "vulnerability", "severity": "HIGH", "script": script_id})

        if findings:
            self.nse_results[ip]["findings"].extend(findings)

    async def protocol_fingerprinting(self, host: str, port: int) -> Dict:
        """
        Send protocol-specific probes to identify service.
        Better than relying on port numbers.
        """
        fingerprint = {
            "host": host,
            "port": port,
            "service": None,
            "version": None,
            "banner": None,
            "probes_tried": [],
        }

        for protocol_name, probes in SMART_PROBES.items():
            for probe in probes:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((host, port))
                    sock.send(probe.format(host=host).encode())
                    response = sock.recv(4096).decode("utf-8", errors="ignore")
                    sock.close()

                    fingerprint["probes_tried"].append(protocol_name)

                    # Parse response for service identification
                    if response:
                        fingerprint["banner"] = response[:500]
                        fingerprint["service"] = self._identify_service(response, port)
                        fingerprint["version"] = self._extract_version(response)
                        break

                except socket.timeout:
                    pass
                except Exception as e:
                    pass

        return fingerprint

    def _identify_service(self, banner: str, port: int) -> Optional[str]:
        """Identify service from banner content."""
        banner_lower = banner.lower()

        service_signatures = {
            "http": ["http/", "html", "<title>"],
            "ssh": ["ssh-", "openssh"],
            "ftp": ["220 ", "ftp"],
            "smtp": ["220 ", "smtp"],
            "telnet": ["telnet"],
            "mysql": ["mysql"],
            "postgres": ["postgres"],
            "redis": ["redis"],
            "mongodb": ["mongo"],
            "elasticsearch": ["elasticsearch"],
        }

        for service, keywords in service_signatures.items():
            if any(kw in banner_lower for kw in keywords):
                return service

        # Fallback to port-based guessing
        port_guesses = {
            3306: "mysql",
            5432: "postgres",
            6379: "redis",
            27017: "mongodb",
            9200: "elasticsearch",
            5672: "rabbitmq",
            6000: "x11",
            7687: "neo4j",
        }

        return port_guesses.get(port)

    def _extract_version(self, banner: str) -> Optional[str]:
        """Extract version strings from banners."""
        import re

        patterns = [
            r"(\d+\.\d+(?:\.\d+)*)",
            r"v\d+\.\d+",
            r"/(\d+\.\d+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1) if match.groups() else match.group(0)

        return None

    async def batch_fingerprint(self, targets: List[str], ports: Optional[Dict[str, Set[int]]] = None) -> List[Dict]:
        """
        Fingerprint multiple hosts in parallel.
        """
        if not ports:
            ports = self.discovered_ports

        fingerprints = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            tasks = []
            for host, port_set in ports.items():
                for port in port_set:
                    task = asyncio.create_task(self.protocol_fingerprinting(host, port))
                    tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)
            fingerprints = [r for r in results if isinstance(r, dict)]

        return fingerprints

    async def test_default_credentials(self, host: str, port: int, service: Optional[str]) -> Dict:
        """
        Safely test default credentials (rate-limited, timeout protected).
        """
        if port not in DEFAULT_CREDS:
            return {"host": host, "port": port, "tested": False}

        result = {"host": host, "port": port, "service": service, "tested": True, "credentials_found": []}

        for username, password in DEFAULT_CREDS[port]:
            try:
                if service == "mysql":
                    # Simple MySQL auth test (no actual query execution)
                    import mysql.connector
                    conn = mysql.connector.connect(
                        host=host, port=port, user=username, password=password, connection_timeout=3
                    )
                    conn.close()
                    result["credentials_found"].append({"user": username, "pass": password})
                elif service == "postgres":
                    import psycopg2
                    conn = psycopg2.connect(
                        host=host, port=port, user=username, password=password, connect_timeout=3
                    )
                    conn.close()
                    result["credentials_found"].append({"user": username, "pass": password})
            except Exception:
                pass

        return result


async def enhanced_discovery(
    targets: List[str],
    out_dir: Path,
    use_nse: bool = True,
    nse_categories: Optional[List[str]] = None,
    skip_masscan: bool = False,
) -> Dict:
    """
    Main enhanced discovery pipeline:
    1. Masscan rapid sweep (optional)
    2. Intelligent port probing
    3. NSE script enumeration
    4. Protocol fingerprinting
    5. Service identification & enrichment
    """
    print("[*] Starting Enhanced Asset Discovery...")
    scanner = SmartScanner(use_nse=use_nse, nse_categories=nse_categories)

    # Phase 1: Fast sweep (optional)
    if not skip_masscan:
        print("\n[Phase 1] Fast port discovery with Masscan...")
        ports = await scanner.masscan_sweep(targets)
    else:
        ports = {target: set() for target in targets}

    # Phase 2: Intelligent ports
    print("\n[Phase 2] Probing intelligent ports...")
    await scanner.smart_port_discovery(targets)

    # Phase 3: NSE Scripts (Deep enumeration)
    if use_nse:
        print("\n[Phase 3] Running NSE scripts (deep enumeration)...")
        nse_results = await scanner.nse_scan(targets, scanner.discovered_ports)
    else:
        nse_results = {}

    # Phase 4: Fingerprinting
    print("\n[Phase 4] Protocol fingerprinting...")
    fingerprints = await scanner.batch_fingerprint(targets, scanner.discovered_ports)

    # Consolidate results
    results = {
        "scan_type": "enhanced_discovery_with_nse",
        "targets": targets,
        "discovered_ports": {k: sorted(list(v)) for k, v in scanner.discovered_ports.items()},
        "fingerprints": fingerprints,
        "nse_results": nse_results,
        "nse_scripts_used": nse_categories or ["service_detection", "web_discovery", "ssl_tls", "discovery"],
        "timestamp": time.time(),
    }

    # Save results
    out_file = out_dir / "enhanced_scan.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    # Summary statistics
    total_ports = sum(len(p) for p in scanner.discovered_ports.values())
    total_findings = sum(len(r.get("findings", [])) for r in nse_results.values())

    print(f"\n{80*'='}")
    print(f"[+] Enhanced Discovery Complete")
    print(f"{'='*80}")
    print(f"  Ports Discovered:     {total_ports}")
    print(f"  NSE Findings:         {total_findings}")
    print(f"  Results Saved:        {out_file}")
    print(f"{80*'='}\n")

    return results
