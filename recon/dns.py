"""
Passive DNS Enumeration Module
Subdomain discovery via crt.sh, HackerTarget, and wordlist enumeration
"""

import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict


def passive_dns_enum(domain: str, scope_cidrs) -> List[Dict]:
    """
    Perform passive DNS enumeration on a target domain

    Args:
        domain: Target domain to enumerate
        scope_cidrs: List of authorised CIDR ranges for filtering

    Returns:
        List of asset dictionaries with discovered subdomains and IPs
    """
    assets = []
    subdomains = set()

    print(f"[*] Starting passive DNS enumeration for {domain}")

    # Run all three discovery methods concurrently
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(query_crtsh, domain): 'crt.sh',
            executor.submit(query_hackertarget, domain): 'HackerTarget',
            executor.submit(wordlist_enum, domain): 'wordlist',
        }
        for future in as_completed(futures):
            source = futures[future]
            try:
                result = future.result()
                subdomains.update(result)
                print(f"[✓] {source} returned {len(result)} subdomain(s)")
            except Exception as e:
                print(f"[!] {source} failed: {e}")

    print(f"[✓] Found {len(subdomains)} unique subdomain(s)")

    # Resolve all subdomains concurrently
    print("[*] Resolving subdomains to IP addresses...")
    from modules.scope import validate_discovered_ip

    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_sub = {executor.submit(resolve_domain, sub): sub for sub in subdomains}
        for future in as_completed(future_to_sub):
            subdomain = future_to_sub[future]
            try:
                ips = future.result()
                for ip in ips:
                    if validate_discovered_ip(ip, scope_cidrs):
                        assets.append({
                            'source': 'passive_dns',
                            'hostname': subdomain,
                            'ip': ip,
                            'ports': [],
                            'services': []
                        })
            except Exception:
                pass

    return assets


def query_crtsh(domain: str) -> set:
    """Query crt.sh certificate transparency logs for subdomains"""
    subdomains = set()

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=30)

        if response.status_code == 200:
            data = response.json()

            for entry in data:
                name = entry.get('name_value', '')
                for subdomain in name.split('\n'):
                    subdomain = subdomain.strip()
                    if subdomain.startswith('*.'):
                        subdomain = subdomain[2:]
                    if subdomain and subdomain.endswith(domain):
                        subdomains.add(subdomain)

    except requests.exceptions.RequestException as e:
        print(f"[!] crt.sh query failed: {e}")
    except Exception as e:
        print(f"[!] Error processing crt.sh results: {e}")

    return subdomains


def query_hackertarget(domain: str) -> set:
    """Query HackerTarget API for subdomains"""
    subdomains = set()

    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=30)

        if response.status_code == 200:
            lines = response.text.split('\n')

            for line in lines:
                if ',' in line:
                    subdomain = line.split(',')[0].strip()
                    if subdomain and subdomain.endswith(domain):
                        subdomains.add(subdomain)

    except requests.exceptions.RequestException as e:
        print(f"[!] HackerTarget query failed: {e}")
    except Exception as e:
        print(f"[!] Error processing HackerTarget results: {e}")

    return subdomains


def wordlist_enum(domain: str) -> set:
    """Enumerate common subdomains using a wordlist"""
    common_prefixes = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'imap',
        'webmail', 'admin', 'portal', 'vpn', 'remote',
        'cloud', 'api', 'dev', 'test', 'staging',
        'prod', 'uat', 'demo', 'blog', 'shop',
        'store', 'support', 'help', 'cdn', 'assets'
    ]

    candidates = [f"{prefix}.{domain}" for prefix in common_prefixes]
    subdomains = set()

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_sub = {executor.submit(resolve_domain, sub): sub for sub in candidates}
        for future in as_completed(future_to_sub):
            subdomain = future_to_sub[future]
            try:
                if future.result():
                    subdomains.add(subdomain)
            except Exception:
                pass

    return subdomains


def resolve_domain(hostname: str) -> List[str]:
    """
    Resolve a hostname to IP addresses

    Args:
        hostname: Hostname to resolve

    Returns:
        List of IP addresses
    """
    ips = []

    try:
        answers = dns.resolver.resolve(hostname, 'A')
        for rdata in answers:
            ips.append(str(rdata))

    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.Timeout:
        pass
    except Exception:
        pass

    return ips
