"""
AI Asset Classification Module
Heuristic rules + optional LLM-based asset classification
"""

import os
import json
import requests
from typing import List, Dict


def classify_assets(assets: List[Dict]) -> List[Dict]:
    """
    Classify assets using heuristic rules and optional LLM enrichment
    
    Args:
        assets: List of asset dictionaries
    
    Returns:
        Assets with added 'asset_type' and 'classification_confidence' fields
    """
    llm_endpoint = os.environ.get('INVENTA_LLM_ENDPOINT')
    
    for asset in assets:
        # Always apply heuristic classification first
        asset_type, confidence = heuristic_classify(asset)
        asset['asset_type'] = asset_type
        asset['classification_confidence'] = confidence
        
        # Optionally enrich with LLM if endpoint is configured
        if llm_endpoint:
            llm_enrichment = llm_classify(asset, llm_endpoint)
            if llm_enrichment:
                asset['llm_classification'] = llm_enrichment
    
    return assets


def heuristic_classify(asset: Dict) -> tuple:
    """
    Classify asset using rule-based heuristics
    
    Args:
        asset: Asset dictionary
    
    Returns:
        Tuple of (asset_type, confidence_score)
    """
    services = asset.get('services', [])
    ports = [p.get('port') for p in asset.get('ports', [])]
    hostname = (asset.get('hostname') or '').lower()
    os_info = asset.get('os', '').lower() if asset.get('os') else ''
    
    # Cloud resources
    if asset.get('cloud_provider'):
        provider = asset.get('cloud_provider')
        resource_type = asset.get('resource_type') or 'Unknown'
        return f"Cloud {resource_type.upper()} ({provider.upper()})", 0.95

    # Inventory module classification
    if asset.get('device_type') and asset.get('device_type') != "Unknown Device":
        return asset['device_type'], 0.88
    
    # Web servers
    if any(s in ['http', 'https', 'apache', 'nginx', 'iis'] for s in services):
        return "Web Server", 0.9
    
    # Database servers
    if any(s in ['mysql', 'postgresql', 'mssql', 'mongodb', 'redis', 'oracle'] for s in services):
        return "Database Server", 0.9
    
    # Mail servers
    if any(s in ['smtp', 'pop3', 'imap', 'exchange'] for s in services):
        return "Mail Server", 0.9
    
    # Domain controllers / AD
    if '389' in ports or '636' in ports or 'ldap' in services:
        if '88' in ports or 'kerberos' in services:
            return "Domain Controller", 0.95
        return "LDAP Server", 0.85
    
    # File servers
    if any(s in ['smb', 'cifs', 'nfs', 'ftp', 'sftp'] for s in services):
        return "File Server", 0.85
    
    # VPN/Remote access
    if any(s in ['openvpn', 'ipsec', 'pptp'] for s in services) or '1194' in ports:
        return "VPN Gateway", 0.85
    
    # Network infrastructure
    if 'router' in hostname or 'gateway' in hostname or 'fw' in hostname:
        return "Network Device", 0.8
    
    if 'switch' in hostname or 'cisco' in os_info or 'juniper' in os_info:
        return "Network Switch", 0.8
    
    # Printers
    if '631' in ports or 'ipp' in services or 'printer' in hostname:
        return "Printer", 0.85
    
    # IoT devices
    if 'iot' in hostname or 'camera' in hostname or 'sensor' in hostname:
        return "IoT Device", 0.7
    
    # Workstations
    if '3389' in ports or 'ms-wbt-server' in services:
        return "Windows Workstation", 0.75
    
    if 'windows' in os_info and not any(s in ['iis', 'mssql', 'exchange'] for s in services):
        return "Windows Workstation", 0.7
    
    if 'linux' in os_info or 'ubuntu' in os_info or 'debian' in os_info:
        return "Linux Server", 0.7
    
    # Default
    if asset.get('ports'):
        return "Unknown Host", 0.5
    
    return "Unclassified", 0.3


def llm_classify(asset: Dict, endpoint: str) -> str:
    """
    Enrich classification using LLM (Ollama or compatible endpoint)
    
    Args:
        asset: Asset dictionary
        endpoint: LLM API endpoint (e.g., http://localhost:11434/v1)
    
    Returns:
        LLM classification string
    """
    try:
        # Build context from asset
        context = f"""
Asset Information:
- IP: {asset.get('ip', 'N/A')}
- Hostname: {asset.get('hostname', 'N/A')}
- OS: {asset.get('os', 'N/A')}
- Open Ports: {', '.join([p.get('port', '') for p in asset.get('ports', [])])}
- Services: {', '.join(asset.get('services', []))}
- Initial Classification: {asset.get('asset_type', 'Unknown')}

Based on this information, provide a concise asset classification and its likely business function in 1-2 sentences.
"""
        
        # Call LLM API
        response = requests.post(
            f"{endpoint}/chat/completions",
            json={
                "model": "llama2",  # Default model, can be configured
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity asset classification expert."},
                    {"role": "user", "content": context}
                ],
                "max_tokens": 100,
                "temperature": 0.3
            },
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('choices', [{}])[0].get('message', {}).get('content', '').strip()
    
    except requests.exceptions.RequestException:
        pass  # LLM unavailable, fall back to heuristic only
    except Exception:
        pass
    
    return None
