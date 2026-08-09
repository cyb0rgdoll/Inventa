"""
Active Directory Enumeration Module
Discover and enumerate Active Directory domain-joined assets
"""

import subprocess
import re
from typing import List, Dict


def enumerate_ad() -> List[Dict]:
    """
    Enumerate Active Directory computers and users
    
    Returns:
        List of AD asset dictionaries
    """
    assets = []
    
    print("  [*] Checking for Active Directory connectivity...")
    
    # Check if we're on a domain-joined system
    if not is_domain_joined():
        print("  [!] System is not domain-joined - skipping AD enumeration")
        return assets
    
    # Enumerate AD computers
    print("  [*] Enumerating AD computers...")
    computers = enumerate_ad_computers()
    assets.extend(computers)
    
    # Enumerate domain controllers
    print("  [*] Identifying domain controllers...")
    dcs = enumerate_domain_controllers()
    assets.extend(dcs)
    
    return assets


def is_domain_joined() -> bool:
    """Check if the current system is joined to an Active Directory domain"""
    try:
        # Linux: Check if realm is configured
        result = subprocess.run(
            ["realm", "list"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout.strip():
            return True
        
        # Alternative: Check for Kerberos configuration
        try:
            with open('/etc/krb5.conf', 'r') as f:
                content = f.read()
                if 'default_realm' in content.lower():
                    return True
        except FileNotFoundError:
            pass
    
    except FileNotFoundError:
        # realm not installed, try alternative checks
        pass
    except Exception:
        pass
    
    return False


def enumerate_ad_computers() -> List[Dict]:
    """Enumerate computers from Active Directory using LDAP queries"""
    computers = []
    
    try:
        # Use ldapsearch if available
        result = subprocess.run(
            [
                "ldapsearch",
                "-x",
                "-LLL",
                "(objectClass=computer)",
                "cn", "dNSHostName", "operatingSystem"
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            # Parse LDAP output
            entries = result.stdout.split('\n\n')
            
            for entry in entries:
                if 'cn:' in entry:
                    computer = {
                        'source': 'active_directory',
                        'asset_type': 'AD Computer',
                        'ports': [],
                        'services': []
                    }
                    
                    # Extract CN (computer name)
                    cn_match = re.search(r'cn:\s*(.+)', entry)
                    if cn_match:
                        computer['hostname'] = cn_match.group(1).strip()
                    
                    # Extract DNS hostname
                    dns_match = re.search(r'dNSHostName:\s*(.+)', entry)
                    if dns_match:
                        computer['fqdn'] = dns_match.group(1).strip()
                    
                    # Extract OS
                    os_match = re.search(r'operatingSystem:\s*(.+)', entry)
                    if os_match:
                        computer['os'] = os_match.group(1).strip()
                    
                    computers.append(computer)
    
    except FileNotFoundError:
        print("  [!] ldapsearch not found - install with: sudo apt-get install ldap-utils")
    except subprocess.TimeoutExpired:
        print("  [!] LDAP query timeout")
    except Exception as e:
        print(f"  [!] AD enumeration failed: {e}")
    
    return computers


def enumerate_domain_controllers() -> List[Dict]:
    """Identify domain controllers in the AD environment"""
    dcs = []
    
    try:
        # Query DNS for domain controllers
        result = subprocess.run(
            ["nslookup", "-type=SRV", "_ldap._tcp.dc._msdcs"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            # Parse nslookup output for DC hostnames
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'service' in line.lower():
                    # Extract DC hostname
                    match = re.search(r'=\s*\d+\s+\d+\s+\d+\s+(.+)\.', line)
                    if match:
                        dc_hostname = match.group(1).strip()
                        
                        dc = {
                            'source': 'active_directory',
                            'asset_type': 'Domain Controller',
                            'hostname': dc_hostname,
                            'ports': [
                                {'port': '389', 'protocol': 'tcp', 'service': 'ldap'},
                                {'port': '636', 'protocol': 'tcp', 'service': 'ldaps'},
                                {'port': '88', 'protocol': 'tcp', 'service': 'kerberos'}
                            ],
                            'services': ['ldap', 'kerberos', 'dns']
                        }
                        dcs.append(dc)
    
    except Exception as e:
        print(f"  [!] DC enumeration failed: {e}")
    
    return dcs
