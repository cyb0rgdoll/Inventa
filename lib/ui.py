"""Interactive UI functions for Inventa."""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from lib.colors import *
from lib.config import WORKFLOWS, API_KEYS, make_scan_args
from lib.utils import load_lines, ensure_dir

DIVIDER = f"{GRAY}{'━'*66}{RESET}"


def clear_screen():
    """Clear terminal screen."""
    try:
        from modules.platform_compat import clear_screen as clear_native
        clear_native()
    except Exception:
        import subprocess
        import shutil
        cmd = "cls" if os.name == "nt" else "clear"
        if shutil.which(cmd):
            subprocess.run([cmd], check=False)


def print_banner():
    """Print Inventa banner with fade-in effect."""
    print(f"{CYAN}{BOLD}")
    print(r"  ___                      _        ")
    print(r" |_ _|_ ____   _____ _ __ | |_ __ _ ")
    print(r"  | || '_ \ \ / / _ \ '_ \| __/ _` |")
    print(r"  | || | | \ V /  __/ | | | || (_| |")
    print(r" |___|_| |_|\_/ \___|_| |_|\__\__,_|")
    print(RESET)
    print(f"{CYAN}{BOLD}Inventa v2.0{RESET} {DIM}— Defensive Asset Discovery Framework{RESET}")
    print(f"{DIM}Developed by cyb0rgdoll | github.com/cyb0rgdoll/inventa{RESET}")
    print(f"{DIM}Authorised environments only{RESET}")
    print()


def print_api_status():
    """Show API key configuration status."""
    print(f"{CYAN}{BOLD}[*] OSINT / API Status{RESET}")
    print(DIVIDER)
    for name, var in API_KEYS:
        val = os.environ.get(var, "")
        if val:
            masked = val[:8] + ('…' if len(val) > 8 else '')
            print(f"  {GREEN}[✓]{RESET} {name:<20} {GRAY}{masked}{RESET}")
        else:
            print(f"  {GRAY}[○]{RESET} {name:<20} {DIM}Not configured{RESET}")
    print()


def show_menu():
    """Display main menu with styled options."""
    print(f"{CYAN}{BOLD}[*] Scan Mode Selection{RESET}")
    print(DIVIDER)
    print()

    menu_items = [
        ("1", "Quick Scan", GREEN, "Fast (low profile, common ports)"),
        ("2", "Standard Scan", YELLOW, "Balanced (banners + OS fingerprinting)"),
        ("3", "Custom Scan", CYAN, "Choose modules interactively"),
        ("4", "Configuration", BLUE, "Setup targets, scope, API keys"),
        ("5", "Browse Results", WHITE, "Open reports and findings"),
        ("6", "Scan History", MAGENTA, "View past scans and changes"),
        ("7", "Exit", GRAY, "Quit Inventa"),
    ]

    for num, title, color, desc in menu_items:
        print(f"  {BOLD}{num}.{RESET} {color}{title:<20}{RESET} {GRAY}{desc}{RESET}")

    print()
    print_api_status()
    print(DIVIDER)
    print()


def open_path(path: Path) -> None:
    """Open a file or folder in the native OS explorer/viewer."""
    try:
        from modules.platform_compat import open_path as open_native
        open_native(path)
    except Exception:
        print(info(f"Open manually: {path}"))


def ask_yes_no(prompt: str) -> bool:
    """Ask user a yes/no question."""
    response = input(f"{GRAY}[?]{RESET} {prompt}? (y/n): ").strip().lower()
    return response in ("y", "yes")


def print_progress(label: str, percent: int, status: str = None):
    """Print a progress bar with percentage."""
    filled = int(percent / 5)
    bar = f"{CYAN}{'█' * filled}{GRAY}{'░' * (20 - filled)}{RESET}"
    status_text = f" {status}" if status else ""
    print(f"  {label:<30} {bar} {percent:>3}%{status_text}")


def latest_report(results_dir: Path):
    """Find the latest HTML report in results directory."""
    reports = list(results_dir.rglob("inventa_report_*.html"))
    return max(reports, key=lambda p: p.stat().st_mtime) if reports else None


def browse_results_menu(results_dir: Path):
    """Interactive menu to browse scan results."""
    print()
    print(f"{BLUE}{BOLD}[→] Browse Results{RESET}")
    print(DIVIDER)
    print()

    ensure_dir(results_dir)
    report = latest_report(results_dir)

    menu_items = [
        ("1", "Open results folder"),
        ("2", "Open latest HTML report"),
        ("3", "Open latest topology map"),
        ("4", "Filter results"),
        ("5", "Back"),
    ]

    for num, title in menu_items:
        print(f"  {BOLD}{num}.{RESET} {title}")

    print()
    choice = input(f"{prompt('Select')}: ").strip()
    if choice == "1":
        open_path(results_dir)
    elif choice == "2":
        if report:
            open_path(report)
        else:
            print(f"\n{warn('No HTML reports found')}\n")
    elif choice == "3":
        topos = list(results_dir.rglob("network_topology.html"))
        if topos:
            open_path(max(topos, key=lambda p: p.stat().st_mtime))
        else:
            print(f"\n{warn('No topology map found')}\n")
    elif choice == "4":
        filter_results_menu(results_dir)


def filter_results_menu(results_dir: Path):
    """Filter and display results from latest JSON scan."""
    import json

    json_files = list(results_dir.rglob("inventa_data_*.json"))
    if not json_files:
        print(f"\n{warn('No results found')}\n")
        return

    latest_json = max(json_files, key=lambda p: p.stat().st_mtime)
    try:
        assets = json.loads(latest_json.read_text())
    except Exception as e:
        print(f"\n{error(f'Failed to load results: {e}')}\n")
        return

    print()
    print(f"{CYAN}{BOLD}[→] Filter Results ({len(assets)} total assets){RESET}")
    print(DIVIDER)
    print()

    menu_items = [
        ("1", "Filter by port number"),
        ("2", "Filter by service name"),
        ("3", "Filter by asset type"),
        ("4", "Show all (table format)"),
        ("5", "Back"),
    ]

    for num, title in menu_items:
        print(f"  {BOLD}{num}.{RESET} {title}")

    print()
    choice = input(f"{prompt('Select')}: ").strip()

    if choice == "1":
        port = input(f"{prompt('Port number')}: ").strip()
        filtered = [a for a in assets if any(
            str(p.get('port')) == port for p in a.get('ports', [])
        )]
        _print_results_table(filtered, f"Port {port}")

    elif choice == "2":
        service = input(f"{prompt('Service name')}: ").strip().lower()
        filtered = [a for a in assets if any(
            service in s.lower() for s in a.get('services', [])
        )]
        _print_results_table(filtered, f"Service {service}")

    elif choice == "3":
        asset_type = input(f"{prompt('Asset type')}: ").strip().lower()
        filtered = [a for a in assets if asset_type in a.get('asset_type', '').lower()]
        _print_results_table(filtered, f"Type {asset_type}")

    elif choice == "4":
        _print_results_table(assets, "All Results")


def _print_results_table(assets, title):
    """Print results in a formatted table."""
    if not assets:
        print(f"\n{warn('No matching results')}\n")
        return

    print()
    print(f"{CYAN}{BOLD}[*] {title} ({len(assets)} asset(s)){RESET}")
    print()
    print(f"{'IP':<18} {'Hostname':<25} {'Type':<20} {'Ports':<15}")
    print(f"{GRAY}{'─'*78}{RESET}")

    for asset in assets:
        ip = asset.get('ip', 'Unknown')[:17]
        hostname = asset.get('hostname', '')[:24]
        asset_type = asset.get('asset_type', 'Unknown')[:19]
        ports = ', '.join(str(p.get('port')) for p in asset.get('ports', [])[:3])
        if len(asset.get('ports', [])) > 3:
            ports += '...'

        print(f"{ip:<18} {hostname:<25} {asset_type:<20} {ports:<15}")

    print(f"{GRAY}{'─'*78}{RESET}\n")


def create_scope_file(path: str):
    """Create scope file interactively."""
    print()
    print(f"{CYAN}{BOLD}[→] Create Scope File{RESET}")
    print(f"{DIM}Enter one CIDR per line. Blank line to finish.{RESET}")
    print()

    lines = ["# Scope file - one CIDR range per line"]
    while True:
        cidr = input(f"  {prompt('CIDR')}: ").strip()
        if not cidr:
            break
        lines.append(cidr)

    if len(lines) <= 1:
        print(f"\n{warn('No ranges entered')}\n")
        return

    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n{success(f'Scope file created: {path}')}\n")


def create_targets_file(path: str):
    """Create targets file interactively."""
    print()
    print(f"{CYAN}{BOLD}[→] Create Targets File{RESET}")
    print(f"{DIM}Enter IPs, hostnames, or CIDRs. Blank line to finish.{RESET}")
    print()

    lines = ["# Targets file - one IP/hostname/CIDR per line"]
    while True:
        target = input(f"  {prompt('Target')}: ").strip()
        if not target:
            break
        lines.append(target)

    if len(lines) <= 1:
        print(f"\n{warn('No targets entered')}\n")
        return

    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n{success(f'Targets file created: {path}')}\n")


def config_menu(scope_file: str, targets_file: str):
    """Configuration menu for setup."""
    scope_path = Path(scope_file)
    targets_path = Path(targets_file)
    editor = os.environ.get("EDITOR", "nano" if os.name != "nt" else "notepad")

    print()
    print(f"{WHITE}{BOLD}[→] Configuration{RESET}")
    print(DIVIDER)
    print()

    scope_label = f"Edit {scope_file}" if scope_path.exists() else f"{YELLOW}Create {scope_file}{RESET}"
    targets_label = (
        f"Edit {targets_file}" if targets_path.exists() else f"{YELLOW}Create {targets_file}{RESET}"
    )

    menu_items = [
        ("1", "Edit .env"),
        ("2", scope_label),
        ("3", targets_label),
        ("4", "Manage scan profiles"),
        ("5", "Back"),
    ]

    for num, title in menu_items:
        print(f"  {BOLD}{num}.{RESET} {title}")

    print()
    choice = input(f"{prompt('Select')}: ").strip()

    if choice == "1":
        try:
            subprocess.run([editor, ".env"])
        except Exception as e:
            print(error(f"Could not open editor: {e}"))
    elif choice == "2":
        if scope_path.exists():
            try:
                subprocess.run([editor, scope_file])
            except Exception as e:
                print(error(f"Could not open editor: {e}"))
        else:
            create_scope_file(scope_file)
    elif choice == "3":
        if targets_path.exists():
            try:
                subprocess.run([editor, targets_file])
            except Exception as e:
                print(error(f"Could not open editor: {e}"))
        else:
            create_targets_file(targets_file)
    elif choice == "4":
        profiles_menu()


def custom_scan_builder(scope_file: str, targets_file: str, results_dir: Path) -> argparse.Namespace:
    """Build custom scan arguments interactively."""
    from datetime import datetime

    if not Path(scope_file).exists() or not Path(targets_file).exists():
        print(f"\n{error('Please create scope and targets files first (Configuration menu)')}\n")
        return None

    print()
    print(f"{MAGENTA}{BOLD}[→] Custom Scan Builder{RESET}")
    print(DIVIDER)
    print()

    profile = input(f"{prompt('Profile')}: (low/medium/high) [medium]: ").strip() or "medium"
    if profile not in ("low", "medium", "high"):
        profile = "medium"

    scan_name = input(f"{prompt('Scan name')}: [custom]: ").strip() or "custom"
    print()
    print(f"{DIM}Choose modules:{RESET}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(results_dir) / "custom" / f"{scan_name}_{timestamp}"

    return make_scan_args(
        scope_file,
        targets_file,
        out,
        profile=profile,
        banner_grab=ask_yes_no("Banner grabbing"),
        fingerprint=ask_yes_no("OS fingerprinting"),
        topology=ask_yes_no("Network topology"),
        osint=ask_yes_no("OSINT enrichment"),
        tls=ask_yes_no("TLS scan"),
        passive_dns=ask_yes_no("Passive DNS"),
        cloud_enum=ask_yes_no("Cloud enumeration"),
        masscan=ask_yes_no("Masscan pre-scan (optional)"),
        subdomain_enum=ask_yes_no("Subdomain enumeration"),
        vuln_check=ask_yes_no("Vulnerability correlation"),
        cloud_scraper=ask_yes_no("Cloud spidering"),
        web_inspect=ask_yes_no("Web inspection"),
        compliance=ask_yes_no("CIS compliance scoring"),
        history=ask_yes_no("Record to history database"),
    )


def profiles_menu():
    """Interactive menu to manage scan profiles."""
    from lib.profiles import list_profiles, delete_profile

    profiles = list_profiles()

    print()
    print(f"{MAGENTA}{BOLD}[→] Manage Scan Profiles{RESET}")
    print(DIVIDER)
    print()

    if profiles:
        print(f"{DIM}Available profiles:{RESET}")
        for idx, profile in enumerate(profiles, 1):
            print(f"  {idx}. {profile}")
        print()

    menu_items = [
        ("L", "Load a profile (into custom scan)"),
        ("D", "Delete a profile"),
        ("B", "Back"),
    ]

    for key, title in menu_items:
        print(f"  {BOLD}{key}.{RESET} {title}")

    print()
    choice = input(f"{prompt('Select')}: ").strip().upper()

    if choice == 'L':
        if not profiles:
            print(f"\n{warn('No profiles available')}\n")
            return
        profile_name = input(f"{prompt('Profile name')}: ").strip()
        if profile_name in profiles:
            print(f"\n{success(f'Profile {profile_name} is ready to load')}")
            print(f"{info('Use: python3 inventa.py --load-profile ' + profile_name)}\n")
        else:
            print(f"\n{error('Profile not found')}\n")

    elif choice == 'D':
        if not profiles:
            print(f"\n{warn('No profiles available')}\n")
            return
        profile_name = input(f"{prompt('Profile to delete')}: ").strip()
        if profile_name in profiles:
            if ask_yes_no(f"Delete profile '{profile_name}'"):
                if delete_profile(profile_name):
                    print(f"\n{success('Profile deleted')}\n")
                else:
                    print(f"\n{error('Failed to delete profile')}\n")
        else:
            print(f"\n{error('Profile not found')}\n")


def history_menu():
    """Interactive menu to browse scan history."""
    from modules.asset_history import query_network_changes, generate_timeline_report

    db_path = Path.home() / ".inventa" / "history.db"
    if not db_path.exists():
        print()
        print(f"{warn('No scan history found')}")
        print(f"{info('Run scans with history enabled (--history or custom scan menu)')}\n")
        return

    print()
    print(f"{BLUE}{BOLD}[→] Scan History{RESET}")
    print(DIVIDER)
    print()

    menu_items = [
        ("1", "Show network changes (last 30 days)"),
        ("2", "Show network changes (all time)"),
        ("3", "Back"),
    ]

    for num, title in menu_items:
        print(f"  {BOLD}{num}.{RESET} {title}")

    print()
    choice = input(f"{prompt('Select')}: ").strip()
    if choice == "1":
        try:
            changes = query_network_changes(db_path, days=30)
            report = generate_timeline_report(changes)
            print(f"\n{report}\n")
        except Exception as e:
            print(f"\n{error(f'Failed to load history: {e}')}\n")
    elif choice == "2":
        try:
            changes = query_network_changes(db_path, days=99999)
            report = generate_timeline_report(changes)
            print(f"\n{report}\n")
        except Exception as e:
            print(f"\n{error(f'Failed to load history: {e}')}\n")
