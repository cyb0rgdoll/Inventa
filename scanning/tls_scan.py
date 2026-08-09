"""
TLS/Certificate Scanning Module
Certificate details, expiry, and cipher analysis
"""

import asyncio
import ssl
import socket
from datetime import datetime
from typing import List, Dict


def scan_tls(assets: List[Dict]) -> List[Dict]:
    """
    Scan TLS/SSL certificates and cipher suites on HTTPS services

    Args:
        assets: List of asset dictionaries

    Returns:
        Assets with added 'tls_info' field containing certificate and cipher data
    """
    return asyncio.run(_scan_tls_async(assets))


async def _scan_tls_async(assets: List[Dict]) -> List[Dict]:
    tasks = []
    for asset in assets:
        ip = asset.get('ip')
        if not ip:
            continue

        https_ports = []
        for port_info in asset.get('ports', []):
            port = port_info.get('port')
            service = port_info.get('service', '').lower()
            if port in ['443', '8443'] or 'https' in service or 'ssl' in service:
                https_ports.append(int(port))

        if https_ports:
            tasks.append(_scan_asset_tls(asset, ip, https_ports))

    await asyncio.gather(*tasks, return_exceptions=True)
    return assets


async def _scan_asset_tls(asset: Dict, ip: str, https_ports: List[int]):
    loop = asyncio.get_event_loop()
    tls_tasks = [
        loop.run_in_executor(None, get_tls_info, ip, port)
        for port in https_ports
    ]
    results = await asyncio.gather(*tls_tasks, return_exceptions=True)

    tls_results = []
    for port, tls_info in zip(https_ports, results):
        if isinstance(tls_info, Exception) or not tls_info:
            continue
        tls_info['port'] = port
        tls_results.append(tls_info)
        print(f"  [+] {ip}:{port} - TLS scan complete")

    if tls_results:
        asset['tls_info'] = tls_results


def get_tls_info(hostname: str, port: int, timeout: int = 5) -> Dict:
    """
    Retrieve TLS/SSL certificate information and cipher details

    Args:
        hostname: Target hostname or IP
        port: Target HTTPS port
        timeout: Connection timeout in seconds

    Returns:
        Dictionary containing TLS information
    """
    tls_info = {}

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                tls_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                tls_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))

                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')

                if not_after:
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    tls_info['expires'] = not_after

                    days_remaining = (expiry_date - datetime.now()).days
                    tls_info['days_until_expiry'] = days_remaining

                    if days_remaining < 0:
                        tls_info['status'] = 'EXPIRED'
                    elif days_remaining < 30:
                        tls_info['status'] = 'EXPIRING SOON'
                    else:
                        tls_info['status'] = 'VALID'

                tls_info['tls_version'] = ssock.version()
                tls_info['cipher'] = ssock.cipher()[0] if ssock.cipher() else None

                san = cert.get('subjectAltName', [])
                tls_info['san'] = [name[1] for name in san if name[0] == 'DNS']

                cipher_name = (tls_info.get('cipher') or '').upper()
                weak_indicators = ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'ANON']

                if any(indicator in cipher_name for indicator in weak_indicators):
                    tls_info['weak_cipher'] = True

                if tls_info['tls_version'] in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                    tls_info['outdated_tls'] = True

    except ssl.SSLError as e:
        tls_info['error'] = f"SSL error: {str(e)}"
    except socket.timeout:
        tls_info['error'] = "Connection timeout"
    except Exception as e:
        tls_info['error'] = str(e)

    return tls_info if tls_info else None
