"""
Time-Series Asset Tracking Module
SQLite database for historical asset tracking and change detection
"""

import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timedelta


def initialize_database(db_path: Path):
    """
    Initialize SQLite database schema for asset tracking
    
    Args:
        db_path: Path to SQLite database file
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Assets table - tracks when assets are first/last seen
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            ip TEXT PRIMARY KEY,
            hostname TEXT,
            asset_type TEXT,
            os TEXT,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            scan_count INTEGER DEFAULT 0
        )
    """)
    
    # Scans table - tracks each scan operation
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP,
            profile TEXT,
            assets_discovered INTEGER,
            duration_seconds REAL
        )
    """)
    
    # Asset snapshots - full asset state at each scan
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset_snapshots (
            snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip TEXT,
            data JSON,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
            FOREIGN KEY (ip) REFERENCES assets(ip)
        )
    """)
    
    # Port changes - track when ports open/close
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS port_changes (
            change_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip TEXT,
            port TEXT,
            protocol TEXT,
            service TEXT,
            change_type TEXT,  -- 'opened', 'closed'
            timestamp TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
            FOREIGN KEY (ip) REFERENCES assets(ip)
        )
    """)
    
    # Service changes - track version updates
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS service_changes (
            change_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip TEXT,
            port TEXT,
            service TEXT,
            old_version TEXT,
            new_version TEXT,
            timestamp TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
            FOREIGN KEY (ip) REFERENCES assets(ip)
        )
    """)
    
    # Vulnerability history
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerability_history (
            vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip TEXT,
            cve_id TEXT,
            cvss_score REAL,
            first_detected TIMESTAMP,
            last_seen TIMESTAMP,
            patched BOOLEAN DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
            FOREIGN KEY (ip) REFERENCES assets(ip)
        )
    """)
    
    # Create indexes for performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_asset_last_seen ON assets(last_seen)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_snapshot_scan ON asset_snapshots(scan_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_port_changes_ip ON port_changes(ip, timestamp)")
    
    conn.commit()
    conn.close()


def record_scan(assets: List[Dict], db_path: Path, profile: str = 'medium', duration: float = 0) -> int:
    """
    Record scan results to database and detect changes
    
    Args:
        assets: List of discovered assets
        db_path: Path to SQLite database
        profile: Scan profile used
        duration: Scan duration in seconds
    
    Returns:
        scan_id of recorded scan
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    timestamp = datetime.now().isoformat()
    
    # Insert scan record
    cursor.execute("""
        INSERT INTO scans (timestamp, profile, assets_discovered, duration_seconds)
        VALUES (?, ?, ?, ?)
    """, (timestamp, profile, len(assets), duration))
    
    scan_id = cursor.lastrowid
    
    # Load all existing assets into memory to avoid N+1 queries
    cursor.execute("SELECT ip, first_seen, scan_count FROM assets")
    existing_assets = {row[0]: (row[1], row[2]) for row in cursor.fetchall()}

    # Process each asset
    for asset in assets:
        ip = asset.get('ip')
        if not ip:
            continue

        hostname = asset.get('hostname')
        asset_type = asset.get('asset_type')
        os = asset.get('os')

        if ip in existing_assets:
            cursor.execute("""
                UPDATE assets
                SET hostname = ?, asset_type = ?, os = ?, last_seen = ?, scan_count = scan_count + 1
                WHERE ip = ?
            """, (hostname, asset_type, os, timestamp, ip))
        else:
            cursor.execute("""
                INSERT INTO assets (ip, hostname, asset_type, os, first_seen, last_seen, scan_count)
                VALUES (?, ?, ?, ?, ?, ?, 1)
            """, (ip, hostname, asset_type, os, timestamp, timestamp))
        
        # Store full asset snapshot
        cursor.execute("""
            INSERT INTO asset_snapshots (scan_id, ip, data)
            VALUES (?, ?, ?)
        """, (scan_id, ip, json.dumps(asset)))
        
        # Detect port changes
        detect_port_changes(cursor, scan_id, ip, asset, timestamp)
        
        # Detect service version changes
        detect_service_changes(cursor, scan_id, ip, asset, timestamp)
        
        # Track vulnerabilities
        track_vulnerabilities(cursor, scan_id, ip, asset, timestamp)
    
    conn.commit()
    conn.close()
    
    return scan_id


def detect_port_changes(cursor, scan_id: int, ip: str, current_asset: Dict, timestamp: str):
    """Detect and record port changes"""
    current_ports = {
        p.get('port'): p 
        for p in current_asset.get('ports', [])
    }
    
    # Get last snapshot for this asset
    cursor.execute("""
        SELECT data FROM asset_snapshots 
        WHERE ip = ? AND scan_id < ?
        ORDER BY scan_id DESC LIMIT 1
    """, (ip, scan_id))
    
    last_snapshot = cursor.fetchone()
    if not last_snapshot:
        # First time seeing this asset - record all ports as "opened"
        for port, port_info in current_ports.items():
            cursor.execute("""
                INSERT INTO port_changes (scan_id, ip, port, protocol, service, change_type, timestamp)
                VALUES (?, ?, ?, ?, ?, 'opened', ?)
            """, (scan_id, ip, port, port_info.get('protocol'), port_info.get('service'), timestamp))
        return
    
    last_asset = json.loads(last_snapshot[0])
    last_ports = {
        p.get('port'): p 
        for p in last_asset.get('ports', [])
    }
    
    # Detect newly opened ports
    new_ports = set(current_ports.keys()) - set(last_ports.keys())
    for port in new_ports:
        port_info = current_ports[port]
        cursor.execute("""
            INSERT INTO port_changes (scan_id, ip, port, protocol, service, change_type, timestamp)
            VALUES (?, ?, ?, ?, ?, 'opened', ?)
        """, (scan_id, ip, port, port_info.get('protocol'), port_info.get('service'), timestamp))
    
    # Detect closed ports
    closed_ports = set(last_ports.keys()) - set(current_ports.keys())
    for port in closed_ports:
        port_info = last_ports[port]
        cursor.execute("""
            INSERT INTO port_changes (scan_id, ip, port, protocol, service, change_type, timestamp)
            VALUES (?, ?, ?, ?, ?, 'closed', ?)
        """, (scan_id, ip, port, port_info.get('protocol'), port_info.get('service'), timestamp))


def detect_service_changes(cursor, scan_id: int, ip: str, current_asset: Dict, timestamp: str):
    """Detect and record service version changes"""
    # Get last snapshot
    cursor.execute("""
        SELECT data FROM asset_snapshots 
        WHERE ip = ? AND scan_id < ?
        ORDER BY scan_id DESC LIMIT 1
    """, (ip, scan_id))
    
    last_snapshot = cursor.fetchone()
    if not last_snapshot:
        return  # No baseline to compare against
    
    last_asset = json.loads(last_snapshot[0])
    
    # Build version maps
    current_versions = {
        p.get('port'): p.get('version')
        for p in current_asset.get('ports', [])
        if p.get('version')
    }
    
    last_versions = {
        p.get('port'): p.get('version')
        for p in last_asset.get('ports', [])
        if p.get('version')
    }
    
    # Detect version changes
    for port, current_version in current_versions.items():
        last_version = last_versions.get(port)
        if last_version and last_version != current_version:
            # Get service name
            service = next(
                (p.get('service') for p in current_asset.get('ports', []) if p.get('port') == port),
                'unknown'
            )
            
            cursor.execute("""
                INSERT INTO service_changes (scan_id, ip, port, service, old_version, new_version, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, ip, port, service, last_version, current_version, timestamp))


def track_vulnerabilities(cursor, scan_id: int, ip: str, asset: Dict, timestamp: str):
    """Track vulnerability lifecycle"""
    current_vulns = asset.get('vulnerabilities', [])
    
    for vuln in current_vulns:
        cve_id = vuln.get('cve_id')
        cvss_score = vuln.get('cvss', 0.0)
        
        if not cve_id:
            continue
        
        # Check if vulnerability already tracked
        cursor.execute("""
            SELECT first_detected, patched FROM vulnerability_history
            WHERE ip = ? AND cve_id = ?
        """, (ip, cve_id))
        
        existing = cursor.fetchone()
        
        if existing:
            # Update last_seen
            cursor.execute("""
                UPDATE vulnerability_history
                SET last_seen = ?, patched = 0
                WHERE ip = ? AND cve_id = ?
            """, (timestamp, ip, cve_id))
        else:
            # New vulnerability
            cursor.execute("""
                INSERT INTO vulnerability_history 
                (scan_id, ip, cve_id, cvss_score, first_detected, last_seen, patched)
                VALUES (?, ?, ?, ?, ?, ?, 0)
            """, (scan_id, ip, cve_id, cvss_score, timestamp, timestamp))
    
    # Mark vulnerabilities as patched if they disappeared
    cursor.execute("""
        UPDATE vulnerability_history
        SET patched = 1
        WHERE ip = ? AND last_seen < ? AND patched = 0
    """, (ip, timestamp))


def query_asset_timeline(ip: str, db_path: Path, days: int = 30) -> Dict:
    """
    Get timeline of changes for a specific asset
    
    Args:
        ip: Asset IP address
        db_path: Path to SQLite database
        days: Number of days to look back
    
    Returns:
        Timeline of changes
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    
    # Get asset info
    cursor.execute("""
        SELECT first_seen, last_seen, scan_count, asset_type, os
        FROM assets WHERE ip = ?
    """, (ip,))
    
    asset_info = cursor.fetchone()
    if not asset_info:
        conn.close()
        return {'error': f'Asset {ip} not found in database'}
    
    first_seen, last_seen, scan_count, asset_type, os = asset_info
    
    # Get port changes
    cursor.execute("""
        SELECT timestamp, port, service, change_type
        FROM port_changes
        WHERE ip = ? AND timestamp >= ?
        ORDER BY timestamp DESC
    """, (ip, cutoff))
    port_changes = cursor.fetchall()
    
    # Get service changes
    cursor.execute("""
        SELECT timestamp, port, service, old_version, new_version
        FROM service_changes
        WHERE ip = ? AND timestamp >= ?
        ORDER BY timestamp DESC
    """, (ip, cutoff))
    service_changes = cursor.fetchall()
    
    # Get vulnerability history
    cursor.execute("""
        SELECT cve_id, cvss_score, first_detected, last_seen, patched
        FROM vulnerability_history
        WHERE ip = ?
        ORDER BY first_detected DESC
    """, (ip,))
    vuln_history = cursor.fetchall()
    
    conn.close()
    
    return {
        'ip': ip,
        'asset_type': asset_type,
        'os': os,
        'first_seen': first_seen,
        'last_seen': last_seen,
        'scan_count': scan_count,
        'port_changes': [
            {'timestamp': t, 'port': p, 'service': s, 'change': c}
            for t, p, s, c in port_changes
        ],
        'service_changes': [
            {'timestamp': t, 'port': p, 'service': s, 'old_version': ov, 'new_version': nv}
            for t, p, s, ov, nv in service_changes
        ],
        'vulnerabilities': [
            {'cve': c, 'cvss': cvss, 'first_detected': fd, 'last_seen': ls, 'patched': bool(p)}
            for c, cvss, fd, ls, p in vuln_history
        ]
    }


def query_network_changes(db_path: Path, days: int = 30) -> Dict:
    """
    Get summary of network-wide changes
    
    Args:
        db_path: Path to SQLite database
        days: Number of days to look back
    
    Returns:
        Summary of changes across all assets
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    
    # New assets
    cursor.execute("""
        SELECT ip, asset_type, first_seen
        FROM assets
        WHERE first_seen >= ?
        ORDER BY first_seen DESC
    """, (cutoff,))
    new_assets = cursor.fetchall()
    
    # Assets not seen recently (potentially offline)
    threshold = (datetime.now() - timedelta(days=7)).isoformat()
    cursor.execute("""
        SELECT ip, asset_type, last_seen
        FROM assets
        WHERE last_seen < ? AND scan_count >= 5
        ORDER BY last_seen ASC
    """, (threshold,))
    missing_assets = cursor.fetchall()
    
    # Recent port changes
    cursor.execute("""
        SELECT ip, port, service, change_type, timestamp
        FROM port_changes
        WHERE timestamp >= ?
        ORDER BY timestamp DESC
        LIMIT 20
    """, (cutoff,))
    port_changes = cursor.fetchall()
    
    # Recent service updates
    cursor.execute("""
        SELECT ip, port, service, new_version, timestamp
        FROM service_changes
        WHERE timestamp >= ?
        ORDER BY timestamp DESC
        LIMIT 20
    """, (cutoff,))
    service_updates = cursor.fetchall()
    
    # New vulnerabilities
    cursor.execute("""
        SELECT ip, cve_id, cvss_score, first_detected
        FROM vulnerability_history
        WHERE first_detected >= ? AND patched = 0
        ORDER BY cvss_score DESC, first_detected DESC
        LIMIT 20
    """, (cutoff,))
    new_vulns = cursor.fetchall()
    
    conn.close()
    
    return {
        'period_days': days,
        'new_assets': [
            {'ip': ip, 'type': t, 'first_seen': fs}
            for ip, t, fs in new_assets
        ],
        'missing_assets': [
            {'ip': ip, 'type': t, 'last_seen': ls}
            for ip, t, ls in missing_assets
        ],
        'port_changes': [
            {'ip': ip, 'port': p, 'service': s, 'change': c, 'timestamp': t}
            for ip, p, s, c, t in port_changes
        ],
        'service_updates': [
            {'ip': ip, 'port': p, 'service': s, 'new_version': nv, 'timestamp': t}
            for ip, p, s, nv, t in service_updates
        ],
        'new_vulnerabilities': [
            {'ip': ip, 'cve': cve, 'cvss': cvss, 'detected': det}
            for ip, cve, cvss, det in new_vulns
        ]
    }


def generate_timeline_report(timeline: Dict) -> str:
    """Generate human-readable timeline report"""
    if 'error' in timeline:
        return f"❌ {timeline['error']}"
    
    report = []
    report.append("=" * 80)
    report.append(f"ASSET TIMELINE: {timeline['ip']}")
    report.append("=" * 80)
    report.append(f"Asset Type: {timeline['asset_type']}")
    report.append(f"Operating System: {timeline['os']}")
    report.append(f"First Seen: {timeline['first_seen']}")
    report.append(f"Last Seen: {timeline['last_seen']}")
    report.append(f"Total Scans: {timeline['scan_count']}")
    report.append("")
    
    if timeline['port_changes']:
        report.append("PORT CHANGES:")
        report.append("-" * 80)
        for change in timeline['port_changes']:
            icon = "🟢" if change['change'] == 'opened' else "🔴"
            report.append(f"{icon} {change['timestamp']}: Port {change['port']} ({change['service']}) {change['change']}")
        report.append("")
    
    if timeline['service_changes']:
        report.append("SERVICE VERSION UPDATES:")
        report.append("-" * 80)
        for change in timeline['service_changes']:
            report.append(f"🔄 {change['timestamp']}: {change['service']} on port {change['port']}")
            report.append(f"   {change['old_version']} → {change['new_version']}")
        report.append("")
    
    if timeline['vulnerabilities']:
        report.append("VULNERABILITY HISTORY:")
        report.append("-" * 80)
        for vuln in timeline['vulnerabilities']:
            status = "✓ PATCHED" if vuln['patched'] else "⚠ ACTIVE"
            report.append(f"{status} {vuln['cve']} (CVSS: {vuln['cvss']})")
            report.append(f"   First detected: {vuln['first_detected']}")
        report.append("")
    
    report.append("=" * 80)
    return '\n'.join(report)
