"""
Compliance Gap Analysis Module
Maps discovered assets to CIS Controls v8.1 framework
"""

from typing import List, Dict
from datetime import datetime


def check_compliance(assets: List[Dict]) -> Dict:
    """
    Analyze network compliance against CIS Controls v8.1
    
    Args:
        assets: List of discovered asset dictionaries
    
    Returns:
        Compliance assessment with scores, gaps, and recommendations
    """
    results = {
        'timestamp': datetime.now().isoformat(),
        'total_assets': len(assets),
        'framework': 'CIS Controls v8.1',
        'overall_score': 0,
        'controls': [],
        'critical_gaps': [],
        'recommendations': []
    }
    
    # CIS Control 1: Inventory and Control of Enterprise Assets
    control_1 = assess_control_1(assets)
    results['controls'].append(control_1)
    
    # CIS Control 2: Inventory and Control of Software Assets
    control_2 = assess_control_2(assets)
    results['controls'].append(control_2)
    
    # CIS Control 3: Data Protection
    control_3 = assess_control_3(assets)
    results['controls'].append(control_3)
    
    # CIS Control 4: Secure Configuration
    control_4 = assess_control_4(assets)
    results['controls'].append(control_4)
    
    # CIS Control 5: Account Management
    control_5 = assess_control_5(assets)
    results['controls'].append(control_5)
    
    # CIS Control 16: Application Software Security
    control_16 = assess_control_16(assets)
    results['controls'].append(control_16)
    
    # Calculate overall score (average of control scores)
    scores = [c['score'] for c in results['controls']]
    results['overall_score'] = sum(scores) / len(scores) if scores else 0
    
    # Identify critical gaps (controls scoring < 50%)
    for control in results['controls']:
        if control['score'] < 50:
            results['critical_gaps'].append({
                'control': control['id'],
                'name': control['name'],
                'score': control['score'],
                'issue': control['gap_description']
            })
    
    # Generate top 5 recommendations
    results['recommendations'] = generate_recommendations(results['controls'], assets)
    
    return results


def assess_control_1(assets: List[Dict]) -> Dict:
    """
    CIS Control 1: Inventory and Control of Enterprise Assets
    Actively manage (inventory, track, and correct) all enterprise assets
    """
    total = len(assets)
    documented = sum(1 for a in assets if a.get('ip') and a.get('asset_type'))
    
    score = (documented / total * 100) if total > 0 else 0
    
    return {
        'id': 'CIS-1',
        'name': 'Inventory and Control of Enterprise Assets',
        'score': score,
        'status': 'PASS' if score >= 90 else 'PARTIAL' if score >= 50 else 'FAIL',
        'findings': f'{documented}/{total} assets documented with type classification',
        'gap_description': f'{total - documented} assets lack complete documentation' if score < 100 else 'All assets documented'
    }


def assess_control_2(assets: List[Dict]) -> Dict:
    """
    CIS Control 2: Inventory and Control of Software Assets
    Actively manage (inventory, track, and correct) all software
    """
    assets_with_services = sum(1 for a in assets if a.get('services'))
    assets_with_versions = sum(1 for a in assets if any(
        p.get('version') for p in a.get('ports', [])
    ))
    
    total = len(assets)
    score = (assets_with_versions / total * 100) if total > 0 else 0
    
    return {
        'id': 'CIS-2',
        'name': 'Inventory and Control of Software Assets',
        'score': score,
        'status': 'PASS' if score >= 80 else 'PARTIAL' if score >= 50 else 'FAIL',
        'findings': f'{assets_with_versions}/{total} assets have software version information',
        'gap_description': 'Insufficient software version detection' if score < 80 else 'Good software inventory'
    }


def assess_control_3(assets: List[Dict]) -> Dict:
    """
    CIS Control 3: Data Protection
    Develop processes and technical controls to identify, classify, and protect data
    """
    # Check for encryption (TLS/HTTPS)
    assets_with_tls = sum(1 for a in assets if a.get('tls_info'))
    web_servers = sum(1 for a in assets if any(
        s in ['http', 'https', 'apache', 'nginx', 'iis'] 
        for s in a.get('services', [])
    ))
    
    score = (assets_with_tls / web_servers * 100) if web_servers > 0 else 100
    
    return {
        'id': 'CIS-3',
        'name': 'Data Protection',
        'score': score,
        'status': 'PASS' if score >= 90 else 'PARTIAL' if score >= 50 else 'FAIL',
        'findings': f'{assets_with_tls}/{web_servers} web servers use TLS/HTTPS',
        'gap_description': f'{web_servers - assets_with_tls} web servers lack TLS encryption' if score < 100 else 'All web traffic encrypted'
    }


def assess_control_4(assets: List[Dict]) -> Dict:
    insecure_assets = set()
    insecure_details = []

    for asset in assets:
        ip = asset.get("ip", "unknown")
        services = asset.get("services", [])
        ports = [p.get("port") for p in asset.get("ports", [])]

        if "telnet" in services or "23" in ports:
            insecure_assets.add(ip)
            insecure_details.append(f"{ip} - Telnet (port 23)")
        if "ftp" in services or "21" in ports:
            insecure_assets.add(ip)
            insecure_details.append(f"{ip} - FTP (port 21)")
        if "445" in ports and "smb" in services:
            insecure_assets.add(ip)
            insecure_details.append(f"{ip} - SMB exposed (port 445)")

    total = len(assets)
    secure_assets = total - len(insecure_assets)
    score = (secure_assets / total * 100) if total > 0 else 100

    return {
        "id": "CIS-4",
        "name": "Secure Configuration",
        "score": score,
        "status": "PASS" if score >= 90 else "PARTIAL" if score >= 70 else "FAIL",
        "findings": f"{secure_assets}/{total} assets have secure service configuration",
        "gap_description": (
            f"Insecure services detected: {'; '.join(insecure_details[:3])}"
            if insecure_details else "No insecure services found"
        ),
    }


def assess_control_5(assets: List[Dict]) -> Dict:
    """
    CIS Control 5: Account Management
    Use processes and tools to manage accounts and credentials
    """
    # Check for default/common ports that may indicate default configs
    assets_with_default_ssh = sum(1 for a in assets if any(
        p.get('port') == '22' and p.get('service') == 'ssh'
        for p in a.get('ports', [])
    ))
    
    total_ssh = sum(1 for a in assets if 'ssh' in a.get('services', []))
    
    # Scoring: assets using non-default ports get higher scores
    score = ((total_ssh - assets_with_default_ssh) / total_ssh * 100) if total_ssh > 0 else 100
    
    # Adjust score - default SSH port is acceptable, so we'll be lenient
    score = max(score, 70) if assets_with_default_ssh else 100
    
    return {
        'id': 'CIS-5',
        'name': 'Account Management',
        'score': score,
        'status': 'PARTIAL',  # Can't fully assess without authentication testing
        'findings': f'{total_ssh} SSH services detected, {assets_with_default_ssh} on default port 22',
        'gap_description': 'Consider changing default SSH ports for security through obscurity'
    }


def assess_control_16(assets: List[Dict]) -> Dict:
    """
    CIS Control 16: Application Software Security
    Manage security of applications
    """
    assets_with_vulns = sum(1 for a in assets if a.get('vulnerabilities'))
    total = len(assets)
    
    # Count critical CVEs
    critical_cves = sum(
        len([v for v in a.get('vulnerabilities', []) if (v.get('cvss') or 0) >= 7.0])
        for a in assets
    )
    
    # Score based on absence of critical vulnerabilities
    score = ((total - assets_with_vulns) / total * 100) if total > 0 else 100
    score = max(score - (critical_cves * 5), 0)  # Penalize critical CVEs heavily
    
    return {
        'id': 'CIS-16',
        'name': 'Application Software Security',
        'score': score,
        'status': 'PASS' if score >= 80 else 'PARTIAL' if score >= 50 else 'FAIL',
        'findings': f'{assets_with_vulns} assets with known vulnerabilities, {critical_cves} critical CVEs',
        'gap_description': f'{critical_cves} critical vulnerabilities require immediate patching' if critical_cves > 0 else 'No critical vulnerabilities detected'
    }


def generate_recommendations(controls: List[Dict], assets: List[Dict]) -> List[str]:
    """
    Generate prioritized remediation recommendations
    
    Args:
        controls: List of assessed controls
        assets: List of discovered assets
    
    Returns:
        List of actionable recommendations
    """
    recommendations = []
    
    # Priority 1: Critical gaps (score < 50)
    critical = [c for c in controls if c['score'] < 50]
    for control in critical:
        recommendations.append(f"🔴 CRITICAL: {control['id']} - {control['gap_description']}")
    
    # Priority 2: Asset-specific issues
    for asset in assets:
        ip = asset.get('ip')
        
        # Check for outdated software
        for port_info in asset.get('ports', []):
            version = port_info.get('version') or ''
            if 'OpenSSH' in version and '10.' not in version:
                recommendations.append(f"🟡 UPDATE: {ip} - Upgrade OpenSSH to version 10.x")
                break
        
        # Check for external exposure with vulnerabilities
        if asset.get('externally_exposed') and asset.get('vulnerabilities'):
            vuln_count = len(asset.get('vulnerabilities', []))
            recommendations.append(f"🔴 CRITICAL: {ip} - Externally exposed with {vuln_count} known vulnerabilities")
    
    # Priority 3: Best practices
    if any('telnet' in a.get('services', []) for a in assets):
        recommendations.append("🟡 HARDEN: Disable Telnet (port 23) and use SSH instead")
    
    if any('ftp' in a.get('services', []) for a in assets):
        recommendations.append("🟡 HARDEN: Replace FTP with SFTP/FTPS for secure file transfer")
    
    # Limit to top 10 recommendations
    return recommendations[:10]


def generate_compliance_report(compliance_results: Dict) -> str:
    """
    Generate human-readable compliance report
    
    Args:
        compliance_results: Compliance assessment dictionary
    
    Returns:
        Formatted text report
    """
    report = []
    report.append("=" * 80)
    report.append("CIS CONTROLS v8.1 COMPLIANCE ASSESSMENT")
    report.append("=" * 80)
    report.append(f"Scan Date: {compliance_results['timestamp']}")
    report.append(f"Total Assets: {compliance_results['total_assets']}")
    report.append(f"Overall Compliance Score: {compliance_results['overall_score']:.1f}/100")
    report.append("")
    
    # Control-by-control breakdown
    report.append("CONTROL ASSESSMENT:")
    report.append("-" * 80)
    for control in compliance_results['controls']:
        status_icon = "✓" if control['status'] == 'PASS' else "⚠" if control['status'] == 'PARTIAL' else "✗"
        report.append(f"{status_icon} {control['id']}: {control['name']}")
        report.append(f"   Score: {control['score']:.1f}/100 ({control['status']})")
        report.append(f"   {control['findings']}")
        report.append("")
    
    # Critical gaps
    if compliance_results['critical_gaps']:
        report.append("CRITICAL GAPS:")
        report.append("-" * 80)
        for gap in compliance_results['critical_gaps']:
            report.append(f"⚠ {gap['control']}: {gap['name']} (Score: {gap['score']:.1f}/100)")
            report.append(f"   Issue: {gap['issue']}")
            report.append("")
    
    # Recommendations
    report.append("PRIORITIZED RECOMMENDATIONS:")
    report.append("-" * 80)
    for idx, rec in enumerate(compliance_results['recommendations'], 1):
        report.append(f"{idx}. {rec}")
    
    report.append("=" * 80)
    
    return '\n'.join(report)
