"""
Fingerprinting Module
OS and device fingerprinting beyond basic Nmap -O
"""

import subprocess
import re
from typing import List, Dict


def fingerprint_assets(assets: List[Dict]) -> List[Dict]:
    """
    Perform advanced OS and device fingerprinting
    
    Args:
        assets: List of asset dictionaries
    
    Returns:
        Assets with enhanced fingerprinting information
    """
    for asset in assets:
        ip = asset.get('ip')
        if not ip:
            continue
        
        # Enhance OS detection with p0f if available
        p0f_result = passive_os_fingerprint(ip)
        if p0f_result:
            asset['passive_os'] = p0f_result
        
        # Analyze TTL for OS hints
        ttl_os = ttl_based_os_detection(ip)
        if ttl_os:
            asset['ttl_os_hint'] = ttl_os
        
        # HTTP header fingerprinting for web servers
        if any(p.get('port') in ['80', '443', '8080', '8443'] for p in asset.get('ports', [])):
            http_fingerprint = http_server_fingerprint(ip)
            if http_fingerprint:
                asset['http_fingerprint'] = http_fingerprint
    
    return assets


def passive_os_fingerprint(ip: str) -> str:
    """
    Attempt passive OS fingerprinting using p0f
    
    Args:
        ip: Target IP address
    
    Returns:
        OS fingerprint string if successful, None otherwise
    """
    try:
        # Check if p0f is available
        result = subprocess.run(
            ["which", "p0f"],
            capture_output=True,
            timeout=2
        )
        
        if result.returncode != 0:
            return None  # p0f not installed
        
        # Run p0f in passive mode (requires previous network capture)
        # This is a simplified implementation - real usage would require
        # integration with packet capture
        
        return None  # Placeholder - p0f requires special setup
    
    except Exception:
        return None


def ttl_based_os_detection(ip: str) -> str:
    """
    Detect OS based on TTL values from ping
    
    Args:
        ip: Target IP address
    
    Returns:
        OS hint based on TTL value
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            # Extract TTL from ping output
            match = re.search(r'ttl=(\d+)', result.stdout, re.IGNORECASE)
            if match:
                ttl = int(match.group(1))
                
                # Common TTL values by OS
                if ttl <= 64:
                    return "Linux/Unix (TTL ≤64)"
                elif ttl <= 128:
                    return "Windows (TTL ≤128)"
                elif ttl <= 255:
                    return "Network Device (TTL ≤255)"
    
    except Exception:
        pass
    
    return None


def http_server_fingerprint(ip: str) -> Dict:
    """
    Fingerprint web server through HTTP headers
    
    Args:
        ip: Target IP address
    
    Returns:
        Dictionary with server fingerprint information
    """
    fingerprint = {}
    
    try:
        import requests
        
        # Try HTTP first
        try:
            response = requests.head(f"http://{ip}", timeout=3, allow_redirects=False)
            
            fingerprint['server'] = response.headers.get('Server', 'Unknown')
            fingerprint['powered_by'] = response.headers.get('X-Powered-By')
            fingerprint['framework'] = response.headers.get('X-AspNet-Version')
            
            # Detect server technology from headers
            server_header = response.headers.get('Server', '').lower()
            
            if 'apache' in server_header:
                fingerprint['technology'] = 'Apache'
            elif 'nginx' in server_header:
                fingerprint['technology'] = 'Nginx'
            elif 'iis' in server_header or 'microsoft' in server_header:
                fingerprint['technology'] = 'IIS'
            elif 'cloudflare' in server_header:
                fingerprint['technology'] = 'Cloudflare'
            
            return fingerprint
        
        except requests.exceptions.RequestException:
            pass
    
    except ImportError:
        pass
    
    return None
