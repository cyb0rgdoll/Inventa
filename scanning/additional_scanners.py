"""
Additional Scanner Integrations for Inventa
Includes: Naabu, ZMap, Smap (passive), Python-Nmap, Libnmap wrappers
"""

import subprocess
import json
import asyncio
from typing import List, Dict, Optional, Set
from pathlib import Path
import ipaddress
import re

def validate_targets(targets: List[str]) -> List[str]:
    """Validate targets to prevent injection."""
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
                    raise ValueError(f"Invalid target: {target}")
    return validated


class NaabuScanner:
    """Fast TCP/UDP port scanner (ProjectDiscovery)"""

    @staticmethod
    def is_installed() -> bool:
        """Check if Naabu is installed"""
        return subprocess.run(["which", "naabu"], capture_output=True).returncode == 0

    @staticmethod
    async def scan(targets: List[str], ports: str = "1-65535", udp: bool = False) -> Dict[str, Set[int]]:
        """
        Scan with Naabu

        Args:
            targets: List of IPs/CIDRs to scan
            ports: Port range (e.g., "1-10000", "80,443,8080")
            udp: Also scan UDP (slower)

        Returns:
            Dict mapping target -> set of open ports
        """
        targets = validate_targets(targets)
        results = {target: set() for target in targets}

        try:
            cmd = ["naabu", "-host", ",".join(targets), "-p", ports]

            if udp:
                cmd.append("-u")

            # Add output options
            cmd.extend(["-json", "-o", "/tmp/naabu_output.json"])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if Path("/tmp/naabu_output.json").exists():
                with open("/tmp/naabu_output.json") as f:
                    for line in f:
                        data = json.loads(line)
                        host = data.get("host")
                        port = data.get("port")
                        if host and port:
                            results[host].add(port)

            return results
        except FileNotFoundError:
            print("[!] Naabu not installed. Install with: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
            return results
        except Exception as e:
            print(f"[!] Naabu scan failed: {e}")
            return results


class ZMapScanner:
    """Internet-scale TCP port scanner"""

    @staticmethod
    def is_installed() -> bool:
        """Check if ZMap is installed"""
        return subprocess.run(["which", "zmap"], capture_output=True).returncode == 0

    @staticmethod
    async def scan(targets: List[str], port: int = 80, output_file: str = "/tmp/zmap_output.json") -> Dict[str, Set[int]]:
        """
        Scan with ZMap (designed for single port scanning at massive scale)

        Args:
            targets: List of IPs/CIDRs
            port: Port to scan (ZMap scans one port at a time)
            output_file: Where to save results

        Returns:
            Dict mapping target -> set of open ports
        """
        targets = validate_targets(targets)
        results = {target: set() for target in targets}

        try:
            # ZMap scans CIDR blocks, so process each target
            for target in targets:
                cmd = [
                    "zmap",
                    "-p", str(port),
                    "-o", output_file,
                    target
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

                if Path(output_file).exists():
                    with open(output_file) as f:
                        for line in f:
                            if line.strip():
                                ip = line.split(',')[0] if ',' in line else line.strip()
                                try:
                                    ipaddress.ip_address(ip)
                                    results[target].add(port)
                                except:
                                    pass

            return results
        except FileNotFoundError:
            print("[!] ZMap not installed. Install with: sudo apt-get install -y zmap")
            return results
        except Exception as e:
            print(f"[!] ZMap scan failed: {e}")
            return results


class SmapScanner:
    """Passive scanner using Shodan API (stealth, zero contact with target)"""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Smap with Shodan API key

        Args:
            api_key: Shodan API key (or set SHODAN_API_KEY env var)
        """
        self.api_key = api_key

    @staticmethod
    def is_installed() -> bool:
        """Check if Smap is installed"""
        return subprocess.run(["which", "smap"], capture_output=True).returncode == 0

    async def scan(self, targets: List[str], ports: str = "1-10000") -> Dict[str, Set[int]]:
        """
        Passive scan using Smap/Shodan

        Note: ZERO contact with target - uses existing Shodan data

        Args:
            targets: List of IPs to query (passive only)
            ports: Port range (informational - doesn't actually scan)

        Returns:
            Dict mapping target -> set of open ports from Shodan
        """
        targets = validate_targets(targets)
        results = {target: set() for target in targets}

        try:
            # Smap accepts nmap-style arguments but queries Shodan instead
            cmd = [
                "smap",
                "-p", ports,
                "-oJ", "/tmp/smap_output.json",
                "--",
                *targets
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if Path("/tmp/smap_output.json").exists():
                with open("/tmp/smap_output.json") as f:
                    data = json.load(f)
                    # Parse Shodan/Smap results
                    if isinstance(data, dict) and "scan" in data:
                        for ip, ports_info in data["scan"].items():
                            for port_info in ports_info:
                                port = port_info.get("portid")
                                if port:
                                    results[ip].add(int(port))

            return results
        except FileNotFoundError:
            print("[!] Smap not installed. Install with: go install -v github.com/nccgroup/smap/cmd/smap@latest")
            return results
        except Exception as e:
            print(f"[!] Smap scan failed: {e}")
            return results


class PythonNmapWrapper:
    """Python-Nmap wrapper for native Nmap integration"""

    def __init__(self):
        """Initialize with python-nmap if available"""
        try:
            import nmap
            self.nm = nmap.PortScanner()
            self.available = True
        except ImportError:
            print("[!] python-nmap not installed: pip install python-nmap")
            self.available = False

    @staticmethod
    def is_installed() -> bool:
        """Check if python-nmap is installed"""
        try:
            import nmap
            return True
        except ImportError:
            return False

    async def scan(self, targets: List[str], ports: str = "1-10000", arguments: str = "-sV -Pn") -> Dict[str, Dict]:
        """
        Native Nmap scanning using Python-Nmap

        Args:
            targets: List of targets
            ports: Port range
            arguments: Additional Nmap arguments

        Returns:
            Dict with detailed Nmap results
        """
        if not self.available:
            return {}

        targets = validate_targets(targets)
        results = {}

        try:
            scan_string = f"{','.join(targets)} -p {ports} {arguments}"
            self.nm.scan(hosts=scan_string)

            for host in self.nm.all_hosts():
                results[host] = {
                    "status": self.nm[host].state(),
                    "protocols": {},
                }

                for proto in self.nm[host].all_protocols():
                    ports_dict = self.nm[host][proto]
                    results[host]["protocols"][proto] = {}

                    for port in ports_dict.keys():
                        results[host]["protocols"][proto][port] = ports_dict[port]['state']

            return results
        except Exception as e:
            print(f"[!] Python-Nmap scan failed: {e}")
            return {}


class LibnmapWrapper:
    """Libnmap wrapper for advanced Nmap manipulation"""

    def __init__(self):
        """Initialize with libnmap if available"""
        try:
            from libnmap.process import NmapProcess
            from libnmap.parser import NmapParser
            self.NmapProcess = NmapProcess
            self.NmapParser = NmapParser
            self.available = True
        except ImportError:
            print("[!] libnmap not installed: pip install python-libnmap")
            self.available = False

    @staticmethod
    def is_installed() -> bool:
        """Check if libnmap is installed"""
        try:
            from libnmap.process import NmapProcess
            return True
        except ImportError:
            return False

    async def scan(self, targets: List[str], ports: str = "1-10000", arguments: str = "-sV -Pn") -> Dict[str, Dict]:
        """
        Advanced Nmap scanning using Libnmap

        Args:
            targets: List of targets
            ports: Port range
            arguments: Additional Nmap arguments

        Returns:
            Dict with structured Nmap results
        """
        if not self.available:
            return {}

        targets = validate_targets(targets)
        results = {}

        try:
            nmap_args = f"-p {ports} {arguments}"
            nm_process = self.NmapProcess(",".join(targets), nmap_args)
            nm_process.run()

            nmap_report = self.NmapParser.parse(nm_process.stdout)

            for host in nmap_report.hosts:
                results[host.address] = {
                    "status": host.status,
                    "services": {}
                }

                for service in host.services:
                    results[host.address]["services"][service.port] = {
                        "state": service.state,
                        "service": service.service_name,
                        "version": service.service_version or "unknown"
                    }

            return results
        except Exception as e:
            print(f"[!] Libnmap scan failed: {e}")
            return {}


# Summary and comparison
AVAILABLE_SCANNERS = {
    "masscan": {"speed": "⚡⚡⚡ (1000x faster)", "coverage": "Wide", "stealthiness": "Low"},
    "nmap": {"speed": "🚀 (baseline)", "coverage": "Comprehensive", "stealthiness": "Low"},
    "naabu": {"speed": "⚡⚡ (Go-based, fast)", "coverage": "Wide", "stealthiness": "Low"},
    "zmap": {"speed": "⚡⚡⚡ (internet-scale)", "coverage": "Internet", "stealthiness": "Low"},
    "smap": {"speed": "🚀 (API lookup)", "coverage": "Public data", "stealthiness": "⚡⚡⚡ (passive)"},
    "python-nmap": {"speed": "🚀 (baseline)", "coverage": "Comprehensive", "stealthiness": "Low"},
    "libnmap": {"speed": "🚀 (baseline)", "coverage": "Comprehensive", "stealthiness": "Low"},
}

if __name__ == "__main__":
    print("Available Scanner Integrations:")
    print("=" * 80)
    for scanner, info in AVAILABLE_SCANNERS.items():
        print(f"\n{scanner.upper()}")
        for key, value in info.items():
            print(f"  {key}: {value}")
