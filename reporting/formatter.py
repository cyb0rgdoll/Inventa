"""
Terminal Output Module
Display scan results in the terminal with rich formatting
"""

import json
from typing import List, Dict
from pathlib import Path


# ANSI color codes
CYAN = "\033[38;5;51m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_scan_summary(assets: List[Dict], duration: float = 0):
    """
    Print comprehensive scan summary to terminal

    Args:
        assets: List of discovered assets
        duration: Scan duration in seconds
    """
    if not assets:
        print(f"\n{YELLOW}No assets discovered{RESET}\n")
        return

    # Overall statistics
    total_assets = len(assets)
    total_ports = sum(len(asset.get('ports', [])) for asset in assets)
    total_services = len(set(
        service
        for asset in assets
        for service in asset.get('services', [])
    ))
    total_vulns = sum(len(asset.get('vulnerabilities', [])) for asset in assets)
    exposed_assets = sum(1 for asset in assets if asset.get('externally_exposed'))

    # Print boxed summary card
    print(f"\n{CYAN}╔{'═' * 78}╗{RESET}")
    print(f"{CYAN}║{RESET} {BOLD}Scan Complete{RESET}{' ' * 63}{CYAN}║{RESET}")
    print(f"{CYAN}╠{'═' * 78}╣{RESET}")

    stats = [
        (f"Assets Discovered", f"{GREEN}{total_assets}{RESET}"),
        (f"Open Ports", f"{total_ports}"),
        (f"Unique Services", f"{total_services}"),
        (f"CVEs Found", f"{RED}{total_vulns}{RESET}" if total_vulns > 0 else "0"),
    ]
    if exposed_assets > 0:
        stats.insert(3, (f"Externally Exposed", f"{YELLOW}{exposed_assets}{RESET}"))
    if duration > 0:
        stats.append((f"Duration", f"{duration:.1f}s"))

    for label, value in stats:
        padded = label + ' ' * (30 - len(label))
        print(f"{CYAN}║{RESET} {padded} {value}{' ' * (46 - len(str(value)))}{CYAN}║{RESET}")

    print(f"{CYAN}╚{'═' * 78}╝{RESET}\n")

    print(f"{BOLD}Detailed Findings:{RESET}\n")

    # Asset-by-asset breakdown
    for idx, asset in enumerate(assets, 1):
        print_asset_detail(asset, idx)


def print_asset_detail(asset: Dict, index: int):
    """
    Print detailed information for a single asset
    
    Args:
        asset: Asset dictionary
        index: Asset number for display
    """
    ip = asset.get('public_ip') or asset.get('ip') or 'Unknown'
    hostname = asset.get('hostname', '')
    asset_type = asset.get('asset_type', 'Unknown Type')
    
    # Header
    header = f"{BOLD}{index}. {ip}{RESET}"
    if hostname:
        header += f" {DIM}({hostname}){RESET}"
    print(header)
    
    # Asset type and OS
    os_info = asset.get('os') or asset.get('ttl_os_hint', '')
    if asset_type != 'Unknown Type':
        print(f"   Type: {asset_type}")
    if asset.get('cloud_provider'):
        print(f"   Cloud: {asset.get('cloud_provider', '').upper()}")
        if asset.get('resource_type'):
            print(f"   Resource: {asset.get('resource_type')}")
        if asset.get('name'):
            print(f"   Name: {asset.get('name')}")
        if asset.get('region'):
            print(f"   Region: {asset.get('region')}")
    if asset.get('public_ip') and asset.get('ip') and asset.get('public_ip') != asset.get('ip'):
        print(f"   Private IP: {asset.get('ip')}")
    if os_info:
        print(f"   OS: {os_info}")
    
    # Ports and services
    ports = asset.get('ports', [])
    if ports:
        print(f"   {GREEN}Open Ports:{RESET}")
        for port_info in ports:
            port = port_info.get('port')
            protocol = port_info.get('protocol', 'tcp')
            service = port_info.get('service', 'unknown')
            version = port_info.get('version', '')
            
            port_line = f"      • {port}/{protocol} - {service}"
            if version:
                port_line += f" ({version})"
            print(port_line)
    
    # Banners
    banners = asset.get('banners', [])
    if banners:
        print(f"   {CYAN}Service Banners:{RESET}")
        for banner_info in banners[:3]:  # Show first 3
            port = banner_info.get('port', '')
            banner = banner_info.get('banner', '')
            if banner:
                # Truncate long banners
                banner_display = banner[:70] + '...' if len(banner) > 70 else banner
                print(f"      [{port}] {banner_display}")
    
    # TLS information
    tls_info = asset.get('tls_info', [])
    if tls_info:
        print(f"   {CYAN}TLS/SSL:{RESET}")
        for tls_data in (tls_info if isinstance(tls_info, list) else [tls_info]):
            port = tls_data.get('port', '?')
            cert_cn = tls_data.get('subject_cn', tls_data.get('cert_cn', 'Unknown'))
            expires = tls_data.get('not_after', tls_data.get('expires', 'Unknown'))
            print(f"      [{port}] CN: {cert_cn}, Expires: {expires}")
    
    # External exposure (OSINT)
    if asset.get('externally_exposed'):
        exposure = asset.get('osint_exposure', {})
        print(f"   {YELLOW}⚠️  EXTERNAL EXPOSURE:{RESET}")
        
        providers = exposure.get('summary', {}).get('providers', [])
        if providers:
            print(f"      Found on: {', '.join(providers)}")
        
        exposure_score = asset.get('exposure_score', 0)
        if exposure_score:
            print(f"      Exposure Score: {exposure_score}/100")
    
    # Vulnerabilities
    vulns = asset.get('vulnerabilities', [])
    if vulns:
        print(f"   {RED}🔴 VULNERABILITIES: {len(vulns)}{RESET}")
        
        # Sort by CVSS score (high to low)
        vulns_sorted = sorted(
            vulns,
            key=lambda v: v.get('cvss') or 0,
            reverse=True
        )
        
        # Show top 5 critical
        for vuln in vulns_sorted[:5]:
            cve_id = vuln.get('cve_id', 'Unknown')
            cvss = vuln.get('cvss', 0)
            severity = get_cvss_severity(cvss)
            
            print(f"      • {cve_id} - CVSS {cvss} ({severity})")
    
    # Compliance issues
    if asset.get('compliance_issues'):
        issues = asset.get('compliance_issues', [])
        print(f"   {YELLOW}⚠️  COMPLIANCE ISSUES: {len(issues)}{RESET}")
        for issue in issues[:3]:  # Show first 3
            print(f"      • {issue}")
    
    print()  # Blank line between assets


def print_compliance_summary(compliance_results: Dict):
    """
    Print CIS Controls compliance summary
    
    Args:
        compliance_results: Compliance assessment results
    """
    print(f"\n{CYAN}{'=' * 80}{RESET}")
    print(f"{BOLD}CIS CONTROLS COMPLIANCE SUMMARY{RESET}")
    print(f"{CYAN}{'=' * 80}{RESET}\n")
    
    overall_score = compliance_results.get('overall_score', 0)
    
    # Color code the overall score
    if overall_score >= 80:
        score_color = GREEN
    elif overall_score >= 50:
        score_color = YELLOW
    else:
        score_color = RED
    
    print(f"Overall Compliance Score: {score_color}{BOLD}{overall_score:.1f}/100{RESET}\n")
    
    # Control-by-control
    print(f"{BOLD}Control Assessment:{RESET}")
    for control in compliance_results.get('controls', []):
        control_id = control.get('id')
        name = control.get('name')
        score = control.get('score', 0)
        status = control.get('status', 'UNKNOWN')
        
        # Status icon
        if status == 'PASS':
            icon = f"{GREEN}✓{RESET}"
        elif status == 'PARTIAL':
            icon = f"{YELLOW}⚠{RESET}"
        else:
            icon = f"{RED}✗{RESET}"
        
        print(f"  {icon} {control_id}: {name}")
        print(f"     Score: {score:.1f}/100 ({status})")
    
    # Critical gaps
    critical_gaps = compliance_results.get('critical_gaps', [])
    if critical_gaps:
        print(f"\n{RED}{BOLD}CRITICAL GAPS:{RESET}")
        for gap in critical_gaps:
            print(f"  🔴 {gap['control']}: {gap['issue']}")
    
    # Top recommendations
    recommendations = compliance_results.get('recommendations', [])
    if recommendations:
        print(f"\n{BOLD}Top Recommendations:{RESET}")
        for idx, rec in enumerate(recommendations[:5], 1):
            print(f"  {idx}. {rec}")
    
    print(f"\n{CYAN}{'=' * 80}{RESET}\n")


def print_quick_stats(assets: List[Dict]):
    """
    Print quick one-line stats during scan
    
    Args:
        assets: List of discovered assets
    """
    if not assets:
        return
    
    total = len(assets)
    with_ports = sum(1 for a in assets if a.get('ports'))
    exposed = sum(1 for a in assets if a.get('externally_exposed'))
    
    print(f"  [→] {total} asset(s) discovered, {with_ports} with open ports", end='')
    if exposed > 0:
        print(f", {YELLOW}{exposed} externally exposed{RESET}", end='')
    print()


def get_cvss_severity(cvss_score: float) -> str:
    """
    Get CVSS severity label
    
    Args:
        cvss_score: CVSS score (0-10)
    
    Returns:
        Severity label
    """
    if cvss_score >= 9.0:
        return f"{RED}CRITICAL{RESET}"
    elif cvss_score >= 7.0:
        return f"{RED}HIGH{RESET}"
    elif cvss_score >= 4.0:
        return f"{YELLOW}MEDIUM{RESET}"
    else:
        return f"{GREEN}LOW{RESET}"


def print_phase_header(phase_name: str, description: str = ""):
    """
    Print a formatted phase header
    
    Args:
        phase_name: Name of the scan phase
        description: Optional description
    """
    print(f"\n{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}[Phase] {phase_name}{RESET}")
    if description:
        print(f"{DIM}{description}{RESET}")
    print(f"{CYAN}{'=' * 60}{RESET}")
