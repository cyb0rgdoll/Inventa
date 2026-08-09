"""
Reporting Module
Generate HTML and CSV reports from discovered assets
"""

import csv
import html
import json
from pathlib import Path
from typing import List, Dict
from datetime import datetime


def _format_ports(ports: List[Dict]) -> str:
    values = []
    for port in ports:
        value = port.get('port', '')
        if value == '' or value is None:
            continue
        values.append(str(value))
    return ', '.join(values)


def _display_ip(asset: Dict) -> str:
    return asset.get('public_ip') or asset.get('ip') or 'N/A'

def _html_text(value) -> str:
    return html.escape(str(value), quote=True)

def _format_discovery_methods(asset: Dict) -> str:
    methods = asset.get('discovery_methods') or []
    if isinstance(methods, str):
        return methods
    return ', '.join(str(method) for method in methods if method)

def _snmp_summary(asset: Dict) -> str:
    snmp = asset.get('snmp') or {}
    if not isinstance(snmp, dict) or not snmp:
        return ''
    values = []
    for key in ('sysName', 'sysDescr', 'sysLocation', 'sysUpTime'):
        value = snmp.get(key)
        if value:
            values.append(f"{key}: {value}")
    if snmp.get('interfaces'):
        values.append(f"interfaces: {len(snmp.get('interfaces', []))}")
    return ' | '.join(values)

def generate_html_report(assets: List[Dict], output_path: Path):
    """
    Generate a professional dark-theme HTML report

    Args:
        assets: List of asset dictionaries
        output_path: Path for HTML output file
    """
    # Calculate statistics
    total_assets = len(assets)
    by_type = {}
    total_vulns = 0
    critical_vulns = 0

    for asset in assets:
        asset_type = asset.get('asset_type', 'Unknown')
        by_type[asset_type] = by_type.get(asset_type, 0) + 1

        vulns = asset.get('vulnerabilities', [])
        total_vulns += len(vulns)

        for vuln in vulns:
            if (vuln.get('cvss') or 0) >= 7.0:
                critical_vulns += 1

    # Build statistics cards
    stat_cards = [
        f'<div class="stat-card"><div class="stat-value">{total_assets}</div><div class="stat-label">Total Assets</div></div>',
        f'<div class="stat-card"><div class="stat-value">{len(by_type)}</div><div class="stat-label">Asset Types</div></div>',
        f'<div class="stat-card warning"><div class="stat-value">{total_vulns}</div><div class="stat-label">Vulnerabilities</div></div>',
        f'<div class="stat-card critical"><div class="stat-value">{critical_vulns}</div><div class="stat-label">Critical CVEs</div></div>',
    ]

    # Build asset rows
    rows = []
    for asset in assets:
        ip = _html_text(_display_ip(asset))
        hostname = _html_text(asset.get('hostname', '-'))
        asset_type = _html_text(asset.get('asset_type', 'Unknown'))
        device_type = _html_text(asset.get('device_type') or asset.get('asset_type', 'Unknown'))
        mac = _html_text(asset.get('mac_address', '-'))
        vendor = _html_text(asset.get('vendor', '-'))
        last_seen = _html_text(asset.get('last_seen', '-'))
        methods = _html_text(_format_discovery_methods(asset) or '-')
        os_info = _html_text(asset.get('os', '-'))
        cloud = _html_text(asset.get('cloud_provider', '-'))
        resource = _html_text(asset.get('resource_type') or asset.get('name') or '-')

        ports_list = _html_text(_format_ports(asset.get('ports', [])))
        services_list = _html_text(', '.join(str(service) for service in asset.get('services', [])))

        vuln_count = len(asset.get('vulnerabilities', []))
        vuln_badge = f'<span class="badge badge-warning">{vuln_count} CVEs</span>' if vuln_count > 0 else ''

        exposed_badge = '<span class="badge badge-critical">EXPOSED</span>' if asset.get('externally_exposed') else ''

        rows.append(f"""
        <tr>
            <td>{ip}</td>
            <td>{hostname}</td>
            <td>{asset_type}</td>
            <td>{device_type}</td>
            <td>{mac}</td>
            <td>{vendor}</td>
            <td>{cloud}</td>
            <td>{resource}</td>
            <td>{os_info}</td>
            <td>{ports_list}</td>
            <td>{services_list}</td>
            <td>{last_seen}</td>
            <td>{methods}</td>
            <td>{vuln_badge} {exposed_badge}</td>
        </tr>
        """)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Use explicit replace() instead of .format() to avoid
    # KeyError collisions with CSS variable curly braces e.g. var(--bg)
    html = (HTML_TEMPLATE
            .replace("{timestamp}", timestamp)
            .replace("{total}", str(total_assets))
            .replace("{stat_cards}", '\n'.join(stat_cards))
            .replace("{rows}", '\n'.join(rows)))

    with open(output_path, 'w') as f:
        f.write(html)


def generate_csv_report(assets: List[Dict], output_path: Path):
    """
    Generate a CSV report for data analysis

    Args:
        assets: List of asset dictionaries
        output_path: Path for CSV output file
    """
    with open(output_path, 'w', newline='') as f:
        fieldnames = [
            'IP', 'Private IP', 'Hostname', 'Asset Type', 'Device Type',
            'MAC Address', 'Vendor', 'First Seen', 'Last Seen', 'Discovery Methods',
            'SNMP Summary', 'Cloud Provider',
            'Resource Type', 'Name', 'Region', 'OS', 'Ports', 'Services',
            'Vulnerabilities', 'Externally Exposed'
        ]

        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for asset in assets:
            writer.writerow({
                'IP': _display_ip(asset),
                'Private IP': asset.get('ip', '') if asset.get('public_ip') != asset.get('ip') else '',
                'Hostname': asset.get('hostname', ''),
                'Asset Type': asset.get('asset_type', 'Unknown'),
                'Device Type': asset.get('device_type', ''),
                'MAC Address': asset.get('mac_address', ''),
                'Vendor': asset.get('vendor', ''),
                'First Seen': asset.get('first_seen', ''),
                'Last Seen': asset.get('last_seen', ''),
                'Discovery Methods': _format_discovery_methods(asset),
                'SNMP Summary': _snmp_summary(asset),
                'Cloud Provider': asset.get('cloud_provider', ''),
                'Resource Type': asset.get('resource_type', ''),
                'Name': asset.get('name', ''),
                'Region': asset.get('region', ''),
                'OS': asset.get('os', ''),
                'Ports': _format_ports(asset.get('ports', [])),
                'Services': ', '.join(asset.get('services', [])),
                'Vulnerabilities': len(asset.get('vulnerabilities', [])),
                'Externally Exposed': 'Yes' if asset.get('externally_exposed') else 'No'
            })


def generate_ndjson_report(assets: List[Dict], output_path: Path):
    """
    Generate NDJSON (newline-delimited JSON) report for piping/streaming

    Args:
        assets: List of asset dictionaries
        output_path: Path for NDJSON output file
    """
    with open(output_path, 'w') as f:
        for asset in assets:
            f.write(json.dumps(asset) + '\n')


# HTML Template (CSS curly braces are safe for .replace() method)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inventa Asset Discovery Report</title>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-dim: #8b949e;
            --primary: #58a6ff;
            --success: #3fb950;
            --warning: #d29922;
            --critical: #f85149;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
            background: var(--bg);
            color: var(--text);
            padding: 20px;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        header {{
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}

        h1 {{
            color: var(--primary);
            font-size: 2em;
            margin-bottom: 10px;
        }}

        .meta {{
            color: var(--text-dim);
            font-size: 0.9em;
        }}

        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px;
            text-align: center;
        }}

        .stat-card.warning {{ border-left: 4px solid var(--warning); }}
        .stat-card.critical {{ border-left: 4px solid var(--critical); }}

        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: var(--primary);
            margin-bottom: 5px;
        }}

        .stat-card.warning .stat-value {{ color: var(--warning); }}
        .stat-card.critical .stat-value {{ color: var(--critical); }}

        .stat-label {{
            color: var(--text-dim);
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            overflow: hidden;
        }}

        thead {{
            background: #1c2128;
        }}

        th {{
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: var(--text);
            border-bottom: 1px solid var(--border);
        }}

        td {{
            padding: 12px;
            border-bottom: 1px solid var(--border);
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        tr:hover {{
            background: #1c2128;
        }}

        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: 500;
            margin-right: 5px;
        }}

        .badge-warning {{
            background: var(--warning);
            color: #000;
        }}

        .badge-critical {{
            background: var(--critical);
            color: #fff;
        }}

        footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--text-dim);
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Inventa Asset Discovery Tool Report 🔍</h1>
            <div class="meta">
                Generated: {timestamp} | Total Assets: {total}
            </div>
        </header>

        <section class="stats">
            {stat_cards}
        </section>

        <section>
            <h2 style="margin-bottom: 15px; color: var(--primary);">Discovered Assets</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>Asset Type</th>
                        <th>Device Type</th>
                        <th>MAC</th>
                        <th>Vendor</th>
                        <th>Cloud</th>
                        <th>Resource</th>
                        <th>Operating System</th>
                        <th>Open Ports</th>
                        <th>Services</th>
                        <th>Last Seen</th>
                        <th>Discovery</th>
                        <th>Alerts</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </section>

        <footer>
            <p>Inventa | Authorised Environments Only</p>
        </footer>
    </div>
</body>
</html>
"""
