#!/usr/bin/env python3
"""
Inventa — Asset Discovery Framework
Run without arguments for the interactive menu, or pass CLI flags for direct scanning.
"""

import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))

from core.scope import load_scope, validate_target
from scanning.active_scan import active_scan
from analysis.classify import classify_assets
from reporting.formatter import print_scan_summary, print_phase_header
from core.platform_compat import clear_screen, is_windows, open_path as open_native_path

# ── ANSI colours ──────────────────────────────────────────────
RED     = '\033[0;31m'
GREEN   = '\033[0;32m'
YELLOW  = '\033[1;33m'
BLUE    = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN    = '\033[0;36m'
WHITE   = '\033[1;37m'
GRAY    = '\033[0;90m'
BOLD    = '\033[1m'
DIM     = '\033[2m'
RESET   = '\033[0m'

SCRIPT_DIR = Path(__file__).parent

CORE_MODULES = [
    ("Active Scanner      ", "scanning/active_scan.py"),
    ("Inventory Discovery ", "scanning/inventory_scan.py"),
    ("Passive DNS         ", "recon/dns.py"),
    ("Cloud Enumeration   ", "recon/cloud.py"),
    ("Banner Grabber      ", "scanning/banner.py"),
    ("Fingerprinter       ", "scanning/fingerprint_lib.py"),
    ("Device Identifier   ", "recon/device.py"),
    ("OSINT Engine        ", "recon/osint.py"),
    ("TLS Analyzer        ", "scanning/tls_scan.py"),
    ("Topology Mapper     ", "core/topology.py"),
    ("Reporter            ", "reporting/reporter.py"),
]

EXPERIMENTAL_MODULES = [
    ("Masscan (fast scan) ", "scanning/tools/masscan_scan.py"),
    ("Subdomain Enum      ", "recon/subdomain.py"),
    ("Smap (passive)      ", "scanning/tools/smap_scan.py"),
    ("Vulnerability Check ", "analysis/vulncheck.py"),
    ("Compliance Checker  ", "analysis/compliance.py"),
    ("AI Classifier       ", "analysis/classify.py"),
    ("Asset History       ", "recon/asset.py"),
    ("Cloud Scraper Recon ", "recon/cloud_scraper.py"),
    ("Web Inspector       ", "recon/web.py"),
    ("Hunter.how Recon    ", "recon/hunter.py"),
    ("AD Enumeration      ", "recon/ad.py"),
    ("NLP Query           ", "analysis/nlp.py"),
    ("Nmap Vulscan        ", "scanning/active_scan.py"),
]

API_KEYS = [
    ("Shodan         ", "SHODAN_API_KEY"),
    ("Censys ID      ", "CENSYS_API_ID"),
    ("BuiltWith      ", "BUILTWITH_API_KEY"),
    ("VirusTotal     ", "VIRUSTOTAL_API_KEY"),
    ("SecurityTrails ", "SECURITYTRAILS_API_KEY"),
    ("Host.io        ", "HOSTIO_API_KEY"),
    ("IPInfo         ", "IPINFO_API_KEY"),
    ("NVD            ", "NVD_API_KEY"),
    ("VulDB          ", "VULDB_API_KEY"),
]


# ── Environment ───────────────────────────────────────────────

def load_env():
    env_file = SCRIPT_DIR / '.env'
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            key, _, val = line.partition('=')
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


# ── Interactive UI ────────────────────────────────────────────

def show_loader():
    steps = [
        "Checking environment",
        "Preparing scan console",
    ]
    print(f"{CYAN}{BOLD}[*] Starting Inventa...{RESET}\n")
    for step in steps:
        print(f"{GRAY}[~]{RESET} {step}...", end='', flush=True)
        time.sleep(0.2)
        print(f" {GREEN}done{RESET}")
    print()


def print_banner():
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


def system_info():
    pyver = sys.version.split()[0]
    if shutil.which('nmap'):
        try:
            out = subprocess.run(['nmap', '--version'], capture_output=True, text=True).stdout
            nmapver = out.split('\n')[0].split()[2]
        except Exception:
            nmapver = 'error'
    else:
        nmapver = 'missing'
    print(f"{GRAY}[i] Python: {pyver} | Nmap: {nmapver}{RESET}")
    print(f"{CYAN}[i] Dir: {BOLD}{SCRIPT_DIR}{RESET}\n")


def check_deps() -> bool:
    missing = [t for t in ('nmap',) if not shutil.which(t)]
    if missing:
        print(f"\n{RED}[!] Missing dependencies: {', '.join(missing)}{RESET}")
        print(f"{YELLOW}[i] Install them before running scans{RESET}\n")
        return False
    return True


def print_module_status():
    divider = f"{GRAY}{'━'*66}{RESET}"
    print(f"{CYAN}{BOLD}[*] Prototype Module Status{RESET}")
    print(divider)

    for name, rel in CORE_MODULES:
        exists = (SCRIPT_DIR / rel).exists()
        mark = f"{GREEN}[✓]{RESET}" if exists else f"{RED}[✗]{RESET}"
        status = name if exists else f"{name} {GRAY}(missing: {rel}){RESET}"
        print(f"  {mark} {status}")

    optional_count = len(EXPERIMENTAL_MODULES)
    print(f"\n{DIM}{optional_count} optional modules available in Custom Scan and CLI help.{RESET}")
    print()


def print_api_status():
    divider = f"{GRAY}{'━'*66}{RESET}"
    print(f"{CYAN}{BOLD}[*] OSINT / API Status{RESET}")
    print(divider)

    for name, var in API_KEYS:
        val = os.environ.get(var, '')
        if val:
            masked = val[:8] + ('…' if len(val) > 8 else '')
            print(f"  {GREEN}[✓]{RESET} {name:<20} {GRAY}{masked}{RESET}")
        else:
            print(f"  {GRAY}[○]{RESET} {name:<20} {DIM}Not configured{RESET}")
    print()


def open_path(path):
    path = Path(path)
    if not open_native_path(path):
        print(f"{GRAY}[i] Open manually: {path}{RESET}")


def latest_report(results_dir: Path):
    reports = list(results_dir.rglob('inventa_report_*.html'))
    return max(reports, key=lambda p: p.stat().st_mtime) if reports else None


def show_menu():
    divider = f"{GRAY}{'━'*58}{RESET}"
    print(f"{CYAN}{BOLD}[*] Inventa Demo Menu{RESET}")
    print(divider)
    print()

    menu_items = [
        ("1", "Quick Check", GREEN, "Fast host/service discovery"),
        ("2", "Inventory Scan", YELLOW, "MAC, vendor, SNMP, device type, reports"),
        ("3", "Lab Demo", CYAN, "Balanced local lab scan with topology"),
        ("4", "Results", BLUE, "Open reports and evidence"),
        ("5", "Configuration", WHITE, "Edit scope and targets"),
        ("6", "Exit", GRAY, "Quit Inventa"),
    ]

    for num, title, color, desc in menu_items:
        print(f"  {BOLD}{num}.{RESET} {color}{title:<16}{RESET} {GRAY}{desc}{RESET}")

    print()
    print(f"{DIM}Advanced OSINT, cloud, web, and custom modules are available through CLI flags.{RESET}")
    print(divider)
    print()


# ── Scan namespace builders ───────────────────────────────────

def _make_args(scope, targets_file, out, profile='low', **flags):
    defaults = dict(
        banner_grab=False, fingerprint=False, vuln_check=False,
        tls=False, topology=False, compliance=False, osint=False,
        ai=False, history=False, no_active=False,
        inventory=False, snmp=False, passive_inventory=False, ssh_deep=False, inventory_db=None,
        agent_import=[],
        passive_dns=False, cloud_enum=False, cloud_scraper=False, web_inspect=False, subdomain_enum=False,
        cloud_enum_osint=False, cloud_keyword=[], cloud_enum_quickscan=True,
        cloud_enum_threads=5, cloud_enum_tool_path=None,
        vhostscan=False, vhostscan_wordlist=None, vhostscan_port=80,
        vhostscan_ssl=False, vhostscan_base_host=None, vhostscan_tool_path=None,
        smap=False, masscan=False, zmap=False, zgrab2=False, hunter=False,
        domain_recon=False,
        striker=False,
        reconspider=False,
        web_suite=False,
        vulscan=False,
        vulners=False,
        zgrab2_module="http",
        websites_file=None,
        report='both',
    )
    defaults.update(flags)
    return argparse.Namespace(
        scope=scope,
        targets_file=targets_file,
        profile=profile,
        out=str(out),
        **defaults,
    )


def _timestamped_out(results_dir, label):
    return Path(results_dir) / f"{label}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


# ── Interactive menu actions ──────────────────────────────────

def _check_scan_files(scope, targets_file) -> bool:
    ok = True
    if not Path(scope).exists():
        print(f"\n{RED}[✗] Scope file not found: {scope}{RESET}")
        print(f"{YELLOW}    Go to Configuration (option 5) to create it.{RESET}")
        ok = False
    if not Path(targets_file).exists():
        print(f"\n{RED}[✗] Targets file not found: {targets_file}{RESET}")
        print(f"{YELLOW}    Go to Configuration (option 5) to create it.{RESET}")
        ok = False
    return ok


def _run_preset(label, scope, targets_file, results_dir, out_label, **flags):
    if not _check_scan_files(scope, targets_file):
        return
    print(f"\n{BOLD}[→] {label}{RESET}\n")
    args = _make_args(scope, targets_file, _timestamped_out(results_dir, out_label), **flags)
    run_inventa(args)


def custom_scan_interactive(scope, targets_file, results_dir):
    if not _check_scan_files(scope, targets_file):
        return
    print(f"\n{MAGENTA}{BOLD}[→] Custom Scan Builder{RESET}\n")

    profile = input(f"{GRAY}[?]{RESET} Profile (low/medium/high) [medium]: ").strip() or 'medium'
    if profile not in ('low', 'medium', 'high'):
        profile = 'medium'

    def ask(prompt):
        return input(f"{GRAY}[?]{RESET} {prompt}? (y/n): ").strip().lower() == 'y'

    scan_name = input(f"{CYAN}[?]{RESET} Scan name [custom]: ").strip() or 'custom'
    out = Path(results_dir) / 'custom' / f"{scan_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    args = _make_args(
        scope, targets_file, out, profile=profile,
        banner_grab=ask("Banner grabbing"),
        fingerprint=ask("OS fingerprinting"),
        inventory=ask("Lansweeper-style inventory enrichment"),
        snmp=ask("SNMP device metadata"),
        passive_inventory=ask("Passive neighbor-cache inventory"),
        ssh_deep=ask("Linux/macOS SSH deep scan"),
        topology=ask("Network topology"),
        osint=ask("OSINT enrichment"),
        tls=ask("TLS scan"),
        passive_dns=ask("Passive DNS enumeration"),
        cloud_enum=ask("Cloud API enumeration"),
        masscan=ask("Fast active port pre-scan (optional)"),
        zmap=ask("Fast active port pre-scan (ZMap)"),
        zgrab2=ask("Application-layer grab (ZGrab2)"),
        web_suite=ask("Website/domain recon suite"),
        subdomain_enum=ask("Subdomain enumeration with Amass/Subfinder/AssetFinder"),
        domain_recon=ask("Domain reconnaissance workflow"),
        striker=ask("Striker external workflow"),
        reconspider=ask("ReconSpider external workflow"),
        cloud_scraper=ask("Cloud indicator spidering"),
        web_inspect=ask("Web application inspection"),
        hunter=ask("Hunter.how OSINT enrichment"),
        vuln_check=ask("CVE vulnerability correlation"),
        vulscan=ask("Nmap vulscan (CVE matching via NSE)"),
        vulners=ask("Nmap vulners (Vulners API via NSE)"),
        compliance=ask("CIS Controls compliance scoring"),
        history=ask("Record scan to local asset history"),
        ai=ask("AI-assisted classification"),
    )

    print(f"\n{MAGENTA}[→] Launching: {scan_name}{RESET}")
    print(f"{GRAY}    Profile: {profile}{RESET}\n")
    run_inventa(args)
    print(f"\n{GREEN}[✓]{RESET} Results saved to: {out}")
    open_path(out)


def browse_results_interactive(results_dir: Path):
    print(f"\n{BLUE}{BOLD}[→] Browse Results{RESET}\n")
    results_dir.mkdir(parents=True, exist_ok=True)
    report = latest_report(results_dir)

    print("  1. Open results folder")
    print("  2. Open latest HTML report")
    print("  3. Open latest topology map")
    print("  4. Back\n")

    choice = input(f"{CYAN}[?]{RESET} Select: ").strip()
    if choice == '1':
        open_path(results_dir)
    elif choice == '2':
        if report:
            open_path(report)
        else:
            print(f"{YELLOW}[!] No HTML reports found{RESET}")
    elif choice == '3':
        topos = list(results_dir.rglob('network_topology.html'))
        if topos:
            open_path(max(topos, key=lambda p: p.stat().st_mtime))
        else:
            print(f"{YELLOW}[!] No topology HTML found{RESET}")


def create_scope_wizard(path: str):
    """Interactively create a scope CIDR file."""
    print(f"\n{CYAN}{BOLD}[→] Create Scope File{RESET}")
    print(f"{GRAY}Enter one CIDR range per line (e.g. 192.168.1.0/24). Blank line to finish.{RESET}\n")
    lines = ["# Inventa Scope File", "# One CIDR range per line\n"]
    while True:
        cidr = input(f"  {GRAY}CIDR:{RESET} ").strip()
        if not cidr:
            break
        lines.append(cidr)
    if len(lines) <= 2:
        print(f"{YELLOW}[!] No ranges entered — file not created.{RESET}")
        return
    Path(path).write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f"{GREEN}[✓]{RESET} Scope file created: {path}")


def create_targets_wizard(path: str):
    """Interactively create a targets file."""
    print(f"\n{CYAN}{BOLD}[→] Create Targets File{RESET}")
    print(f"{GRAY}Enter one IP, hostname, or CIDR per line. Blank line to finish.{RESET}\n")
    lines = ["# Inventa Targets File", "# One IP / hostname / CIDR per line\n"]
    while True:
        target = input(f"  {GRAY}Target:{RESET} ").strip()
        if not target:
            break
        lines.append(target)
    if len(lines) <= 2:
        print(f"{YELLOW}[!] No targets entered — file not created.{RESET}")
        return
    Path(path).write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f"{GREEN}[✓]{RESET} Targets file created: {path}")


def config_menu_interactive(scope_file, targets_file):
    scope_path   = Path(scope_file)
    targets_path = Path(targets_file)
    editor = os.environ.get('EDITOR', 'nano')
    if is_windows() and editor in ("nano", "vim", "vi"):
        editor = "notepad"

    print(f"\n{WHITE}{BOLD}[→] Configuration{RESET}\n")
    print(f"  1. Edit .env")

    scope_label   = f"Edit   {scope_file}" if scope_path.exists()   else f"{YELLOW}Create {scope_file}{RESET}"
    targets_label = f"Edit   {targets_file}" if targets_path.exists() else f"{YELLOW}Create {targets_file}{RESET}"
    print(f"  2. {scope_label}")
    print(f"  3. {targets_label}")
    print("  4. Back\n")

    choice = input(f"{CYAN}[?]{RESET} Select: ").strip()

    if choice == '1':
        try:
            subprocess.run([editor, str(SCRIPT_DIR / '.env')])
        except Exception as e:
            print(f"{RED}[!] Could not open editor: {e}{RESET}")
    elif choice == '2':
        if scope_path.exists():
            try:
                subprocess.run([editor, scope_file])
            except Exception as e:
                print(f"{RED}[!] Could not open editor: {e}{RESET}")
        else:
            create_scope_wizard(scope_file)
    elif choice == '3':
        if targets_path.exists():
            try:
                subprocess.run([editor, targets_file])
            except Exception as e:
                print(f"{RED}[!] Could not open editor: {e}{RESET}")
        else:
            create_targets_wizard(targets_file)


def interactive_mode():
    scope_file  = os.environ.get('SCOPE_FILE',   str(SCRIPT_DIR / 'scope.txt'))
    targets_file = os.environ.get('TARGETS_FILE', str(SCRIPT_DIR / 'targets.txt'))
    results_dir  = Path(os.environ.get('RESULTS_DIR', str(SCRIPT_DIR / 'results')))

    clear_screen()
    show_loader()
    print_banner()
    system_info()
    check_deps()
    show_menu()

    choice = input(f"{CYAN}[?]{RESET} Select option: ").strip()

    if choice == '1':
        _run_preset("Quick Check", scope_file, targets_file, results_dir, 'quick',
                    profile='low')
    elif choice == '2':
        _run_preset("Inventory Scan", scope_file, targets_file, results_dir, 'inventory',
                    profile='medium', banner_grab=True, fingerprint=True,
                    inventory=True, snmp=True)
    elif choice == '3':
        _run_preset("Lab Demo", scope_file, targets_file, results_dir, 'lab',
                    profile='medium', banner_grab=True, fingerprint=True,
                    topology=True, inventory=True, snmp=True)
    elif choice == '4':
        browse_results_interactive(results_dir)
    elif choice == '5':
        config_menu_interactive(scope_file, targets_file)
    elif choice == '6':
        print(f"\n{GRAY}Exiting Inventa...{RESET}\n")
        sys.exit(0)
    else:
        print(f"\n{RED}[!] Invalid option{RESET}\n")
        sys.exit(1)


# ── CLI argument parser ───────────────────────────────────────

def print_simple_help() -> None:
    print("""Inventa - simple asset discovery

Use the menu:
  python3 inventa.py

Common commands:
  python3 inventa.py quick              Fast network discovery
  python3 inventa.py scan               Balanced scan and HTML/CSV report
  python3 inventa.py inventory          Scan plus MAC/vendor/device inventory
  python3 inventa.py domain example.com Domain and subdomain recon
  python3 inventa.py web example.com    Website inspection
  python3 inventa.py cloud aws          Cloud inventory: aws, azure, gcp, all
  python3 inventa.py results            Open saved results
  python3 inventa.py doctor             Check local tools

Default files:
  scope.txt    Authorized CIDR ranges
  targets.txt  Hosts, IPs, or CIDR ranges to assess
  .env         Optional API keys

Advanced:
  python3 inventa.py examples
  python3 inventa.py --advanced-help
""")


def parse_args():
    if any(arg in ("-h", "--help") for arg in sys.argv[1:]) and "--advanced-help" not in sys.argv[1:]:
        print_simple_help()
        raise SystemExit(0)

    argv = ["--help" if arg == "--advanced-help" else arg for arg in sys.argv[1:]]
    epilog = """Easy commands:
  python3 inventa.py quick
  python3 inventa.py scan
  python3 inventa.py inventory
  python3 inventa.py domain example.com
  python3 inventa.py web example.com
  python3 inventa.py cloud aws
  python3 inventa.py results

Power-user examples:
  python3 inventa.py -s scope.txt -t targets.txt -W quick
  python3 inventa.py -d example.com -W domain
  python3 inventa.py -d example.com --cloudscraper
"""
    p = argparse.ArgumentParser(
        description="Inventa Asset Discovery Tool — pass no arguments for interactive mode",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=epilog,
    )

    p.add_argument(
        "command",
        nargs="?",
        choices=[
            "examples", "doctor", "quick", "scan", "standard", "inventory", "assess",
            "results", "domain", "web", "cloudscraper", "scrape", "cloud", "aws", "azure",
        ],
        help=argparse.SUPPRESS,
    )
    p.add_argument("command_target", nargs="?", help=argparse.SUPPRESS)

    # ── Required ──────────────────────────────────────────────
    p.add_argument("-s", "--scope",    help="Path to scope CIDR file")
    p.add_argument("-t", "--targets",  dest="targets_file", help="Path to targets file")
    p.add_argument("-w", "--websites", dest="websites_file", help="Optional path to website/domain targets file")
    p.add_argument("-d", "--domain", action="append", default=[],
                   help="LazyRecon-style domain target shortcut, e.g. -d example.com")
    p.add_argument("--scope-cidr", action="append", default=[],
                   help="Inline scope CIDR (repeatable), e.g. --scope-cidr 192.168.1.0/24")
    p.add_argument("--target", action="append", default=[],
                   help="Inline active target (repeatable), e.g. --target 192.168.1.10 --target host.local")
    p.add_argument("--website", action="append", default=[],
                   help="Inline website/domain target (repeatable), e.g. --website example.com")

    # ── Scan control ──────────────────────────────────────────
    p.add_argument("-p", "--profile",  default="medium", choices=["low", "medium", "high"],
                   help="Scan intensity: low | medium | high  (default: medium)")
    p.add_argument("-o", "--out",      default="results", help="Output directory  (default: results)")
    p.add_argument("-r", "--report",   default="both",  choices=["html", "csv", "both", "none"],
                   help="Report format  (default: both)")
    p.add_argument("--passive",        action="store_true", dest="no_active", help="Skip nmap — passive/OSINT only")
    p.add_argument("--exclude", dest="exclude_file", help="Path to exclusions file (CIDR, IP, domain, wildcard, keyword)")
    p.add_argument("-e", "--exclude-list", default="",
                   help="Comma-separated exclusions, e.g. -e old.example.com,10.0.0.0/24,*cdn*")
    p.add_argument("--doctor", action="store_true", help="Check local OS, Python, tool, and cloud CLI readiness")
    p.add_argument("--examples", action="store_true", help="Show common beginner-friendly commands and exit")
    p.add_argument("--advanced-help", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--results", action="store_true", help="Open saved scan results")
    p.add_argument("--list-workflows", action="store_true", help="Show workflow presets and exit")
    p.add_argument("-W", "--workflow", choices=["quick", "standard", "inventory", "domain", "cloud", "web", "full"],
                   help="Run a compact workflow preset instead of selecting many module flags")
    p.add_argument("--quick", action="store_true", help="Shortcut preset: low profile, minimal active discovery")
    p.add_argument("--standard", action="store_true", help="Shortcut preset: balanced scan with banners, fingerprinting, and passive DNS")
    p.add_argument("--full", action="store_true", help="Shortcut preset: broad scan with cloud, OSINT, TLS, topology, and subdomains")
    p.add_argument("--inventory", action="store_true",
                   help="Lansweeper-style inventory enrichment: ARP/nmap host discovery, MAC/vendor, device type, SQLite")
    p.add_argument("--snmp", action="store_true",
                   help="Collect SNMP metadata during --inventory when snmpwalk is available")
    p.add_argument("--passive-inventory", action="store_true",
                   help="Add neighbor-cache discovery from ip neigh / arp -an during --inventory")
    p.add_argument("--ssh-deep", action="store_true",
                   help="Optional Linux/macOS deep inventory over key-based SSH using INVENTA_SSH_USER")
    p.add_argument("--inventory-db",
                   help="SQLite path for --inventory persistence (default: output dir inventory_assets.sqlite)")
    p.add_argument("--agent-import", action="append", default=[],
                   help="Import endpoint agent JSON inventory file (repeatable)")

    # ── Module flags ──────────────────────────────────────────
    p.add_argument("--banner",   action="store_true", dest="banner_grab",    help="Grab service banners")
    p.add_argument("--fp",       action="store_true", dest="fingerprint",    help="OS fingerprinting + device ID")
    p.add_argument("--tls",      action="store_true",                        help="TLS/SSL certificate analysis")
    p.add_argument("--topo",     action="store_true", dest="topology",       help="Network topology map")
    p.add_argument("--osint",    action="store_true",                        help="OSINT enrichment (Shodan, BuiltWith, VT, Censys…)")
    p.add_argument("--pdns",     action="store_true", dest="passive_dns",    help="Passive DNS enumeration for domain targets")
    p.add_argument("--cloud-enum", action="store_true", dest="cloud_enum",   help="Enumerate cloud assets via configured AWS/Azure/GCP CLIs")
    p.add_argument("--cloud-provider", default="aws", choices=["aws", "azure", "gcp", "all"], help="Cloud provider to enumerate (default: aws)")
    p.add_argument("--provider", dest="cloud_provider", choices=["aws", "azure", "gcp", "all"], help="Alias for --cloud-provider")
    p.add_argument("--cloud-enum-tool", "--cloudenum", action="store_true", dest="cloud_enum_osint",
                   help="Run initstring/cloud_enum keyword-based public cloud OSINT")
    p.add_argument("--cloud-keyword", action="append", default=[],
                   help="Keyword for initstring/cloud_enum (repeatable)")
    p.add_argument("--cloud-enum-full", action="store_false", dest="cloud_enum_quickscan",
                   help="Use full cloud_enum mutations instead of quickscan")
    p.add_argument("--cloud-enum-threads", type=int, default=5,
                   help="Threads for initstring/cloud_enum (default: 5)")
    p.add_argument("--cloud-enum-path", dest="cloud_enum_tool_path",
                   help="Path to initstring/cloud_enum cloud_enum.py")
    p.add_argument("--aws", action="store_true", help="Shortcut: cloud-only AWS enumeration")
    p.add_argument("--azure", action="store_true", help="Shortcut: cloud-only Azure enumeration")
    p.add_argument("--mass",     action="store_true", dest="masscan",        help="Fast active port pre-scan (optional)")
    p.add_argument("--zmap",     action="store_true",                        help="Fast active port pre-scan using ZMap")
    p.add_argument("--zgrab2",   action="store_true",                        help="Application-layer scan using ZGrab2")
    p.add_argument("--zgrab2-module", default="http",                        help="ZGrab2 module to run (default: http)")
    p.add_argument("--web-suite", action="store_true",                       help="Run the website/domain recon suite (domain recon, Striker, ReconSpider, ZGrab2, web inspection)")
    p.add_argument("--recon",    action="store_true", dest="domain_recon",   help="Run domain reconnaissance with subfinder, assetfinder, amass, httpx, nmap, and nuclei")
    p.add_argument("--striker",  action="store_true",                        help="Run the Striker external reconnaissance workflow")
    p.add_argument("--reconspider", action="store_true",                     help="Run the ReconSpider external reconnaissance workflow")
    p.add_argument("--vulscan",  action="store_true",                        help="Nmap NSE vulscan — match service versions to CVEs")
    p.add_argument("--vulners",  action="store_true",                        help="Nmap NSE vulners — query Vulners API for versioned services")
    p.add_argument("--subdomains", action="store_true", dest="subdomain_enum", help="Find subdomains with Amass, Subfinder, and AssetFinder")

    p.add_argument("--ai",       action="store_true",                        help="Run explicit AI-assisted asset classification")
    p.add_argument("--hist",     action="store_true", dest="history",        help="Record scan results to the local SQLite asset history database")
    p.add_argument("--cloud", "--cloudscraper", action="store_true", dest="cloud_scraper",
                   help="Run cloud indicator spidering via CloudScraper and native checks")
    p.add_argument("--web",      action="store_true", dest="web_inspect",    help="Run web application inspection via native checks, inSp3ctor, and Nikto")
    p.add_argument("--vhostscan", action="store_true",
                   help="Run Codingo/VHostScan virtual host discovery")
    p.add_argument("--vhostscan-wordlist",
                   help="Wordlist for VHostScan")
    p.add_argument("--vhostscan-port", type=int, default=80,
                   help="Port for VHostScan (default: 80)")
    p.add_argument("--vhostscan-ssl", action="store_true",
                   help="Use HTTPS for VHostScan")
    p.add_argument("--vhostscan-base-host",
                   help="Base host used for VHostScan wordlist substitution")
    p.add_argument("--vhostscan-path", dest="vhostscan_tool_path",
                   help="Path to VHostScan.py or VHostScan executable")
    p.add_argument("--subs",     action="store_true", dest="subdomain_enum", help="Alias for --subdomains")
    p.add_argument("--smap",     action="store_true",                        help="Passive port scan backed by Shodan InternetDB via Smap")
    p.add_argument("--hunter",   action="store_true",                        help="Run Hunter.how email and personnel OSINT enrichment")
    p.add_argument("--vuln",     action="store_true", dest="vuln_check",     help="Correlate discovered services with CVE intelligence")
    p.add_argument("--cis",      action="store_true", dest="compliance",     help="Generate CIS Controls-style compliance scoring")

    args = p.parse_args(argv)
    _apply_easy_command(args, p)
    _apply_default_files(args)
    if args.workflow:
        _apply_workflow(args, args.workflow)
    if args.aws:
        args.cloud_enum = True
        args.cloud_provider = "aws"
        args.no_active = True
    if args.azure:
        args.cloud_enum = True
        args.cloud_provider = "azure"
        args.no_active = True
    if args.quick:
        _apply_workflow(args, "quick")
    if args.standard:
        _apply_workflow(args, "standard")
    if args.full:
        _apply_workflow(args, "full")
    if (
        args.cloud_enum_osint
        and "--provider" not in sys.argv
        and "--cloud-provider" not in sys.argv
        and not args.aws
        and not args.azure
    ):
        args.cloud_provider = "all"
    if args.domain and args.cloud_scraper and not args.targets_file and not args.target:
        args.no_active = True
    if args.cloud_enum_osint and not any([args.target, args.targets_file, args.domain, args.website, args.websites_file]):
        args.no_active = True
    if args.vhostscan and not args.target and not args.targets_file and not args.website and not args.websites_file:
        args.no_active = True
    if args.domain and not any([
        args.domain_recon, args.web_suite, args.subdomain_enum, args.striker,
        args.reconspider, args.zgrab2, args.web_inspect, args.passive_dns,
        args.cloud_scraper,
    ]):
        args.domain_recon = True
        args.no_active = True
    return args


def _apply_default_files(args) -> None:
    if getattr(args, "scope", None) or getattr(args, "scope_cidr", []):
        return
    needs_active_scope = not getattr(args, "no_active", False) or getattr(args, "inventory", False)
    default_scope = SCRIPT_DIR / "scope.txt"
    if needs_active_scope and default_scope.exists():
        args.scope = str(default_scope)

    has_target_source = any([
        getattr(args, "targets_file", None),
        getattr(args, "target", []),
        getattr(args, "domain", []),
        getattr(args, "website", []),
        getattr(args, "websites_file", None),
        getattr(args, "cloud_enum", False),
        getattr(args, "agent_import", []),
    ])
    default_targets = SCRIPT_DIR / "targets.txt"
    if not has_target_source and default_targets.exists():
        args.targets_file = str(default_targets)


def _apply_easy_command(args, parser) -> None:
    command = getattr(args, "command", None)
    target = getattr(args, "command_target", None)
    if not command:
        return

    if command == "examples":
        args.examples = True
    elif command == "doctor":
        args.doctor = True
    elif command == "results":
        args.results = True
    elif command == "quick":
        _apply_workflow(args, "quick")
    elif command in {"scan", "standard"}:
        _apply_workflow(args, "standard")
    elif command == "inventory":
        _apply_workflow(args, "inventory")
    elif command == "assess":
        _apply_workflow(args, "full")
    elif command == "aws":
        args.aws = True
    elif command == "azure":
        args.azure = True
    elif command == "cloud":
        provider = target or "all"
        if provider not in {"aws", "azure", "gcp", "all"}:
            parser.error("cloud command expects provider: aws, azure, gcp, or all")
        args.cloud_enum = True
        args.cloud_provider = provider
        args.no_active = True
    elif command == "domain":
        if not target:
            parser.error("domain command requires a domain, e.g. python3 inventa.py domain example.com")
        args.domain.append(target)
        _apply_workflow(args, "domain")
    elif command == "web":
        if not target:
            parser.error("web command requires a domain, e.g. python3 inventa.py web example.com")
        args.domain.append(target)
        args.web_inspect = True
        args.zgrab2 = True
        args.no_active = True
    elif command in {"cloudscraper", "scrape"}:
        if not target:
            parser.error("cloudscraper command requires a domain, e.g. python3 inventa.py cloudscraper example.com")
        args.domain.append(target)
        args.cloud_scraper = True
        args.no_active = True


def print_examples() -> None:
    print("""Inventa quick commands
======================

Use the menu:
  python3 inventa.py

Check your system:
  python3 inventa.py doctor

Fast network discovery:
  python3 inventa.py quick

Balanced scan:
  python3 inventa.py scan

Inventory-focused scan:
  python3 inventa.py inventory

Domain recon:
  python3 inventa.py domain example.com

Website inspection:
  python3 inventa.py web example.com

Cloud resource spidering:
  python3 inventa.py cloudscraper example.com

Cloud account inventory:
  python3 inventa.py cloud aws
  python3 inventa.py cloud azure
  python3 inventa.py cloud all

Open results:
  python3 inventa.py results

Advanced flags:
  python3 inventa.py --advanced-help
""")


def print_workflows() -> None:
    print("""Inventa workflows
================

quick     Low-profile active discovery.
standard  Balanced scan with banners, fingerprinting, passive DNS, and inventory enrichment.
inventory Standard scan plus device inventory output.
domain    Domain/subdomain recon using Amass/Subfinder/AssetFinder when installed.
cloud     AWS/Azure/GCP account inventory through configured CLIs.
web       Website/domain inspection with web tooling.
full      Broad authorized workflow with inventory enrichment.
""")


def _apply_workflow(args, workflow: str) -> None:
    if workflow == "quick":
        args.profile = "low"
    elif workflow == "standard":
        args.profile = "medium"
        args.banner_grab = True
        args.fingerprint = True
        args.passive_dns = True
        args.inventory = True
        args.snmp = True
    elif workflow == "inventory":
        args.profile = "medium"
        args.banner_grab = True
        args.fingerprint = True
        args.inventory = True
        args.snmp = True
    elif workflow == "domain":
        args.profile = "low"
        args.domain_recon = True
        args.subdomain_enum = True
        args.no_active = True
    elif workflow == "cloud":
        args.cloud_enum = True
        args.no_active = True
    elif workflow == "web":
        args.profile = "low"
        args.web_suite = True
        args.web_inspect = True
        args.zgrab2 = True
        args.no_active = True
    elif workflow == "full":
        args.profile = "medium"
        args.banner_grab = True
        args.fingerprint = True
        args.inventory = True
        args.snmp = True
        args.topology = True
        args.tls = True
        args.osint = True
        args.passive_dns = True
        args.cloud_enum = True
        args.subdomain_enum = True
        args.domain_recon = True


# ── Core scan engine ──────────────────────────────────────────

def load_targets(targets_file: str):
    if not targets_file:
        return []
    targets = []
    with open(targets_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def _load_scope_inline(scope_values):
    cidrs = []
    for value in scope_values or []:
        try:
            cidrs.append(ipaddress.IPv4Network(value, strict=False))
        except ValueError as e:
            print(f"  [!] Invalid inline CIDR skipped: {value} ({e})")
    return cidrs


def _merge_unique(items):
    merged = []
    seen = set()
    for item in items:
        key = str(item).strip()
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def is_domain_target(target: str) -> bool:
    value = str(target).strip()
    if not value or "." not in value or " " in value:
        return False
    if _is_url_target(value):
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        return True


def _is_url_target(target: str) -> bool:
    return urlparse(str(target).strip()).scheme in {"http", "https"}


def _target_host(target: str) -> str:
    value = str(target).strip()
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"}:
        return parsed.hostname or value
    if ":" in value:
        parsed = urlparse(f"//{value}")
        if parsed.hostname:
            return parsed.hostname
    return value


def _url_port(target: str) -> str:
    parsed = urlparse(str(target).strip())
    if parsed.port:
        return str(parsed.port)
    return "443" if parsed.scheme == "https" else "80"


def _web_asset_from_url(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.hostname or url
    scheme = parsed.scheme or "http"
    return {
        "source": "website_target",
        "url": url,
        "hostname": host,
        "fqdn": host,
        "ports": [
            {
                "port": _url_port(url),
                "protocol": "tcp",
                "service": scheme,
            }
        ],
        "services": [scheme],
    }


def _merge_unique_values(existing, incoming):
    values = []
    seen = set()
    for item in [*(existing or []), *(incoming or [])]:
        key = json.dumps(item, sort_keys=True, default=str) if isinstance(item, dict) else str(item)
        if key in seen:
            continue
        seen.add(key)
        values.append(item)
    return values


def _merge_asset_record(base: dict, incoming: dict) -> dict:
    for key, value in incoming.items():
        if value in (None, "", [], {}):
            continue
        if key in {"ports", "services", "banners", "vulnerabilities", "tls_info"}:
            base[key] = _merge_unique_values(base.get(key, []), value)
        elif key == "source":
            base["sources"] = _merge_unique_values(base.get("sources", [base.get("source")]), [value])
        elif key not in base or base.get(key) in (None, "", [], {}):
            base[key] = value
    return base


def _asset_merge_keys(asset: dict):
    keys = []
    for field in ("public_ip", "ip"):
        value = asset.get(field)
        if value:
            keys.append(str(value))
    if asset.get("url"):
        host = _target_host(asset["url"])
        if host:
            keys.append(host)
    return list(dict.fromkeys(keys))


def _merge_related_assets(assets):
    merged = []
    index = {}

    for asset in assets:
        keys = _asset_merge_keys(asset)
        match = next((index[key] for key in keys if key in index), None)
        if match is None:
            merged.append(asset)
            match = asset
        elif asset.get("cloud_provider") and not match.get("cloud_provider"):
            merged.remove(match)
            match = _merge_asset_record(asset, match)
            merged.append(match)
        else:
            match = _merge_asset_record(match, asset)

        for key in _asset_merge_keys(match):
            index[key] = match

    return merged


def run_inventa(args):
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    start_time = time.time()

    print(f"\n{'='*60}")
    print(f"  Inventa v2.0 — Asset Discovery")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    # ── Scope ─────────────────────────────────────────────────
    print_phase_header("Scope Loading")
    try:
        scope_cidrs = []
        if getattr(args, "scope", None):
            scope_cidrs.extend(load_scope(args.scope))
        scope_cidrs.extend(_load_scope_inline(getattr(args, "scope_cidr", [])))
        scope_cidrs = _merge_unique(scope_cidrs)
        no_active_targets = not getattr(args, "targets_file", None) and not getattr(args, "target", [])
        scope_optional = (
            getattr(args, "cloud_enum", False)
            or getattr(args, "domain", [])
            or getattr(args, "agent_import", [])
        ) and no_active_targets
        if not scope_cidrs and not scope_optional:
            raise ValueError("No valid scope ranges provided. Use --scope and/or --scope-cidr.")
        if scope_cidrs:
            print(f"  [✓] Loaded {len(scope_cidrs)} CIDR range(s)")
        else:
            print("  [✓] No active network targets: no scope file required")
    except Exception as e:
        print(f"  [✗] Failed to load scope: {e}")
        return

    # ── Targets ───────────────────────────────────────────────
    print_phase_header("Target Validation")
    try:
        from core.exclusions import ExclusionRules, load_exclusions

        inline_exclusions = [
            item.strip()
            for item in str(getattr(args, "exclude_list", "") or "").split(",")
            if item.strip()
        ]
        loaded_exclusions = load_exclusions(getattr(args, "exclude_file", None))
        exclusions = ExclusionRules([*loaded_exclusions.patterns, *inline_exclusions])
        raw_targets = []
        raw_targets.extend(load_targets(getattr(args, "targets_file", None)))
        raw_targets.extend(getattr(args, "target", []) or [])
        raw_targets = _merge_unique(raw_targets)
        url_targets = [target for target in raw_targets if _is_url_target(target)]

        website_targets = []
        website_targets.extend(load_targets(getattr(args, "websites_file", None)))
        website_targets.extend(getattr(args, "website", []) or [])
        website_targets.extend(getattr(args, "domain", []) or [])
        website_targets.extend(url_targets)
        website_targets = _merge_unique(website_targets)

        original_target_count = len(raw_targets) + len(website_targets)
        raw_targets = exclusions.filter_targets(raw_targets)
        website_targets = exclusions.filter_targets(website_targets)
        excluded_count = original_target_count - len(raw_targets) - len(website_targets)
        if excluded_count:
            print(f"  [✓] {excluded_count} target(s) excluded")

        normalized_raw_targets = [
            _target_host(t)
            for t in raw_targets
            if not _is_url_target(t)
        ]
        domain_targets = [
            t for t in normalized_raw_targets
            if is_domain_target(t) and validate_target(t, scope_cidrs)
        ]
        domain_targets.extend([t for t in website_targets if is_domain_target(t)])
        domain_targets = sorted(set(domain_targets))
        web_url_targets = [
            t for t in website_targets
            if _is_url_target(t) and validate_target(_target_host(t), scope_cidrs)
        ]
        targets = [t for t in normalized_raw_targets if validate_target(t, scope_cidrs)]
        print(f"  [✓] {len(targets)} active target(s) in scope")
        if domain_targets:
            print(f"  [✓] {len(domain_targets)} domain target(s) available for passive DNS")
        if web_url_targets:
            print(f"  [✓] {len(web_url_targets)} URL target(s) available for web inspection")
        if website_targets:
            print(f"  [✓] {len(website_targets)} website/domain target(s) loaded from separate file")
        out_of_scope = [
            t for t in raw_targets
            if _target_host(t) not in targets and t not in domain_targets and t not in web_url_targets
        ]
        if out_of_scope:
            print(f"  [!] {len(out_of_scope)} target(s) out of scope — skipped")
        if (
            not targets and not domain_targets and not web_url_targets
            and not args.cloud_enum
            and not getattr(args, "agent_import", [])
        ):
            print("  [✗] No in-scope targets. Exiting.")
            return
    except Exception as e:
        print(f"  [✗] Failed to load targets: {e}")
        return

    assets = []

    if getattr(args, "web_suite", False):
        args.domain_recon = True
        args.striker = True
        args.reconspider = True
        args.zgrab2 = True
        args.web_inspect = True

    if getattr(args, "web_inspect", False) and web_url_targets:
        assets.extend(_web_asset_from_url(url) for url in web_url_targets)

    # ── Endpoint agent import ────────────────────────────────
    for agent_file in getattr(args, "agent_import", []) or []:
        print_phase_header("Endpoint Agent Import")
        try:
            from scanning.agent_import import import_agent_assets
            agent_assets = import_agent_assets(agent_file)
            assets.extend(agent_assets)
            print(f"  [✓] Imported {len(agent_assets)} endpoint asset(s) from {agent_file}")
        except Exception as e:
            print(f"  [✗] Agent import failed for {agent_file}: {e}")

    # ── Passive DNS enumeration ──────────────────────────────
    if args.passive_dns:
        print_phase_header("Passive DNS Enumeration")
        try:
            from modules.passive_dns import passive_dns_enum

            if not domain_targets:
                print("  [!] No domain targets supplied - skipping passive DNS")
            else:
                pdns_assets = []
                for domain in domain_targets:
                    pdns_assets.extend(passive_dns_enum(domain, scope_cidrs))
                assets.extend(pdns_assets)
                print(f"  [✓] {len(pdns_assets)} asset(s) discovered via passive DNS")
        except Exception as e:
            print(f"  [✗] Passive DNS failed: {e}")

    # ── Cloud enumeration ────────────────────────────────────
    if args.cloud_enum:
        print_phase_header("Cloud Enumeration")
        try:
            from modules.cloud_enum import cloud_enumerate

            # Ensure AWS default region is set if not already
            if 'AWS_DEFAULT_REGION' not in os.environ and 'AWS_REGION' not in os.environ:
                os.environ['AWS_DEFAULT_REGION'] = 'ap-southeast-2'

            provider = getattr(args, 'cloud_provider', 'aws')
            cloud_assets = cloud_enumerate(provider)
            assets.extend(cloud_assets)
            print(f"  [✓] {len(cloud_assets)} cloud asset(s) enumerated")
        except Exception as e:
            print(f"  [✗] Cloud enumeration failed: {e}")

    if getattr(args, "cloud_enum_osint", False):
        print_phase_header("Cloud Enum OSINT (initstring/cloud_enum)")
        try:
            from modules.cloud_enum_external import run_cloud_enum_external
            keywords = []
            keywords.extend(getattr(args, "cloud_keyword", []) or [])
            keywords.extend(getattr(args, "domain", []) or [])
            keywords.extend(website_targets)
            keywords.extend(_target_host(t) for t in raw_targets if _is_url_target(t))
            cloud_enum_assets = run_cloud_enum_external(
                keywords=keywords,
                out_dir=out_dir,
                provider=getattr(args, "cloud_provider", "all"),
                quickscan=getattr(args, "cloud_enum_quickscan", True),
                threads=getattr(args, "cloud_enum_threads", 5),
                tool_path=getattr(args, "cloud_enum_tool_path", None),
            )
            assets.extend(cloud_enum_assets)
        except Exception as e:
            print(f"  [✗] cloud_enum OSINT failed: {e}")

    if getattr(args, "vhostscan", False):
        print_phase_header("Virtual Host Discovery (VHostScan)")
        try:
            from modules.vhostscan import run_vhostscan
            vhost_targets = []
            vhost_targets.extend(_target_host(t) for t in raw_targets if t)
            vhost_targets.extend(_target_host(t) for t in website_targets if t)
            vhost_assets = run_vhostscan(
                targets=vhost_targets,
                out_dir=out_dir,
                base_host=getattr(args, "vhostscan_base_host", None),
                port=getattr(args, "vhostscan_port", 80),
                ssl=getattr(args, "vhostscan_ssl", False),
                wordlist=getattr(args, "vhostscan_wordlist", None),
                tool_path=getattr(args, "vhostscan_tool_path", None),
            )
            assets.extend(vhost_assets)
        except Exception as e:
            print(f"  [✗] VHostScan failed: {e}")

    # ── Masscan (fast pre-scan) ───────────────────────────────
    if args.masscan:
        print_phase_header("Fast Port Scan (Masscan)", f"Profile: {args.profile}")
        try:
            from scanning.tools.masscan_scan import run_masscan
            masscan_assets = run_masscan(targets, args.profile, out_dir)
            assets.extend(masscan_assets)
            print(f"  [✓] {len(masscan_assets)} host(s) with open ports found by masscan")
        except Exception as e:
            print(f"  [✗] Masscan failed: {e}")

    if getattr(args, "domain_recon", False):
        print_phase_header("Quick Domain Recon")
        try:
            from modules.domain_recon import run_domain_recon
            recon_assets = run_domain_recon(domain_targets, out_dir)
            assets.extend(recon_assets)
            print(f"  [✓] Domain recon produced {len(recon_assets)} asset(s)")
        except Exception as e:
            print(f"  [✗] Domain recon failed: {e}")

    if getattr(args, "striker", False):
        print_phase_header("Striker External Workflow")
        try:
            from scanning.tools.striker_scan import run_striker
            striker_assets = run_striker(domain_targets, out_dir)
            assets.extend(striker_assets)
            print(f"  [✓] Striker produced {len(striker_assets)} asset(s)")
        except Exception as e:
            print(f"  [✗] Striker failed: {e}")

    if getattr(args, "reconspider", False):
        print_phase_header("ReconSpider External Workflow")
        try:
            from scanning.tools.reconspider_scan import run_reconspider
            assets = run_reconspider(domain_targets, assets, out_dir)
            print("  [✓] ReconSpider completed")
        except Exception as e:
            print(f"  [✗] ReconSpider failed: {e}")

    if getattr(args, "zmap", False):
        print_phase_header("Fast Port Scan (ZMap)", f"Profile: {args.profile}")
        try:
            from scanning.tools.zmap_scan import run_zmap
            zmap_assets = run_zmap(targets, args.profile, out_dir)
            assets.extend(zmap_assets)
            print(f"  [✓] {len(zmap_assets)} host(s) with open ports found by zmap")
        except Exception as e:
            print(f"  [✗] ZMap failed: {e}")

    # ── Active scan ───────────────────────────────────────────
    if not args.no_active and targets:
        enrichments = []
        if getattr(args, "vulscan", False):
            enrichments.append("vulscan")
        if getattr(args, "vulners", False):
            enrichments.append("vulners")
        enrichment_label = f" + {', '.join(enrichments)}" if enrichments else ""
        print_phase_header(f"Active Scan (nmap{enrichment_label})", f"Profile: {args.profile}")
        try:
            nmap_assets = active_scan(
                targets, args.profile, out_dir,
                vulscan=getattr(args, "vulscan", False),
                vulners=getattr(args, "vulners", False),
            )
            assets.extend(nmap_assets)
            print(f"  [✓] {len(nmap_assets)} asset(s) discovered by nmap")
            if getattr(args, "vulscan", False):
                vulscan_vulns = sum(
                    sum(1 for v in a.get("vulnerabilities", []) if v.get("source") == "vulscan")
                    for a in nmap_assets
                )
                if vulscan_vulns:
                    print(f"  [✓] Vulscan matched {vulscan_vulns} CVE(s) from service versions")
            if getattr(args, "vulners", False):
                vulners_vulns = sum(
                    sum(1 for v in a.get("vulnerabilities", []) if v.get("source") == "vulners")
                    for a in nmap_assets
                )
                if vulners_vulns:
                    print(f"  [✓] Vulners matched {vulners_vulns} CVE(s) from versioned services")
        except Exception as e:
            print(f"  [✗] Active scan failed: {e}")
    elif not args.no_active:
        print("  [!] Active scan skipped: no validated active targets")

    if getattr(args, "zgrab2", False):
        print_phase_header("Application Grab (ZGrab2)", f"Module: {getattr(args, 'zgrab2_module', 'http')}")
        try:
            from scanning.tools.zgrab2_scan import run_zgrab2
            zgrab_targets = []
            zgrab_targets.extend(domain_targets)
            zgrab_targets.extend(
                a.get("ip") for a in assets
                if a.get("ip")
            )
            zgrab_assets = run_zgrab2(
                zgrab_targets,
                out_dir,
                module=getattr(args, "zgrab2_module", "http"),
            )
            assets.extend(zgrab_assets)
            print(f"  [✓] ZGrab2 completed for {len(zgrab_assets)} target(s)")
        except Exception as e:
            print(f"  [✗] ZGrab2 failed: {e}")

    # ── Smap (passive Shodan-backed scan) ─────────────────────
    if args.smap:
        print_phase_header("Passive Port Scan (Smap / Shodan)")
        try:
            from scanning.tools.smap_scan import run_smap
            smap_assets = run_smap(targets, out_dir)
            assets.extend(smap_assets)
            print(f"  [✓] {len(smap_assets)} asset(s) found via Smap")
        except Exception as e:
            print(f"  [✗] Smap failed: {e}")

    # ── Inventory enrichment ─────────────────────────────────
    if getattr(args, "inventory", False):
        print_phase_header("Inventory Discovery (Lansweeper-style)")
        try:
            from scanning.inventory_scan import enrich_inventory

            inventory_targets = _merge_unique([
                *targets,
                *(str(cidr) for cidr in scope_cidrs),
            ])
            db_arg = getattr(args, "inventory_db", None)
            inventory_db = Path(db_arg) if db_arg else None
            assets = enrich_inventory(
                assets,
                inventory_targets,
                out_dir,
                snmp=getattr(args, "snmp", False),
                passive=getattr(args, "passive_inventory", False),
                ssh_deep=getattr(args, "ssh_deep", False),
                db_path=inventory_db,
            )
            typed = sum(1 for asset in assets if asset.get("device_type"))
            print(f"  [✓] Inventory enriched {len(assets)} asset(s); {typed} device type(s) assigned")
            print(f"  [✓] Inventory CSV: {out_dir / 'inventory_assets.csv'}")
            print(f"  [✓] Inventory DB: {inventory_db or (out_dir / 'inventory_assets.sqlite')}")
        except Exception as e:
            print(f"  [✗] Inventory enrichment failed: {e}")

    # ── Subdomain Enumeration ─────────────────────────────────
    if args.subdomain_enum:
        print_phase_header("Subdomain Enumeration (Amass + Subfinder)")
        try:
            from recon.subdomain import run_subdomain_enum
            subdomain_targets = _merge_unique([*targets, *domain_targets])
            new_assets = run_subdomain_enum(subdomain_targets, assets, scope_cidrs, out_dir)
            assets.extend(new_assets)
            print(f"  [✓] {len(new_assets)} subdomain(s) discovered and resolved")
        except Exception as e:
            print(f"  [✗] Subdomain enumeration failed: {e}")

    assets = _merge_related_assets(assets)

    # ── AI Classification ─────────────────────────────────────
    if assets and getattr(exclusions, "patterns", []):
        before = len(assets)
        assets = exclusions.filter_assets(assets)
        removed = before - len(assets)
        if removed:
            print(f"  [✓] {removed} discovered asset(s) removed by exclusions")

    # ── AI Classification ─────────────────────────────────────
    if assets:
        print_phase_header("Asset Classification")
        try:
            assets = classify_assets(assets)
            print(f"  [✓] {len(assets)} asset(s) classified")
        except Exception as e:
            print(f"  [✗] Classification failed: {e}")

    # ── Banner grabbing ───────────────────────────────────────
    if args.banner_grab and assets:
        print_phase_header("Banner Grabbing")
        try:
            from scanning.banner import banner_grabbing
            assets = banner_grabbing(assets)
            grabbed = sum(1 for a in assets if a.get("banners"))
            print(f"  [✓] Banners grabbed from {grabbed} asset(s)")
        except Exception as e:
            print(f"  [✗] Banner grabbing failed: {e}")

    # ── Fingerprinting ────────────────────────────────────────
    if args.fingerprint and assets:
        print_phase_header("OS Fingerprinting")
        try:
            from scanning.fingerprint_lib import fingerprint_assets
            from recon.device import identify_devices
            assets = fingerprint_assets(assets)
            assets = identify_devices(assets)
            print(f"  [✓] Fingerprinting complete")
        except Exception as e:
            print(f"  [✗] Fingerprinting failed: {e}")

    # ── Vulnerability correlation ─────────────────────────────
    if args.vuln_check and assets:
        print_phase_header("Vulnerability Correlation (CVE)")
        try:
            from analysis.vulncheck import correlate_vulnerabilities
            assets = correlate_vulnerabilities(assets)
            vuln_assets = sum(1 for a in assets if a.get("vulnerabilities"))
            total_vulns = sum(len(a.get("vulnerabilities", [])) for a in assets)
            print(f"  [✓] {total_vulns} CVE(s) found across {vuln_assets} asset(s)")
        except Exception as e:
            print(f"  [✗] Vulnerability check failed: {e}")

    # ── TLS scanning ──────────────────────────────────────────
    if args.tls and assets:
        print_phase_header("TLS/Certificate Analysis")
        try:
            from scanning.tls_scan import scan_tls
            assets = scan_tls(assets)
            tls_assets = sum(1 for a in assets if a.get("tls_info"))
            print(f"  [✓] TLS info gathered for {tls_assets} asset(s)")
        except Exception as e:
            print(f"  [✗] TLS scan failed: {e}")

    # ── OSINT ─────────────────────────────────────────────────
    if args.osint and assets:
        print_phase_header("OSINT Enrichment")
        try:
            from recon.osint import osint_lookup
            assets = osint_lookup(assets)
            exposed = sum(1 for a in assets if a.get("externally_exposed"))
            print(f"  [✓] {exposed} asset(s) found in external sources")
        except Exception as e:
            print(f"  [✗] OSINT failed: {e}")

    # ── Cloud Scraper Recon ───────────────────────────────────
    if args.cloud_scraper:
        print_phase_header("Cloud Asset Spidering (CloudScraper)")
        try:
            from recon.cloud_scraper import run_cloud_scraper
            if not assets and domain_targets:
                assets.extend(
                    {
                        "source": "domain_target",
                        "hostname": domain,
                        "fqdn": domain,
                        "domain": domain,
                        "ports": [],
                        "services": [],
                    }
                    for domain in domain_targets
                )
            if assets:
                assets = run_cloud_scraper(assets, out_dir)
                if getattr(exclusions, "patterns", []):
                    before = len(assets)
                    assets = exclusions.filter_assets(assets)
                    removed = before - len(assets)
                    if removed:
                        print(f"  [✓] {removed} cloud scraper asset(s) removed by exclusions")
                scraped = sum(1 for a in assets if a.get("cloud_scraper_findings"))
                print(f"  [✓] Cloud indicators found in {scraped} asset(s)")
            else:
                print("  [!] CloudScraper skipped: provide -d/--domain, --websites, or discovered assets")
        except Exception as e:
            print(f"  [✗] Cloud scraper failed: {e}")

    # ── Web Application Inspection ────────────────────────────
    if args.web_inspect and assets:
        print_phase_header("Web Application Inspection (inSp3ctor)")
        try:
            from recon.web import run_web_inspector
            assets = run_web_inspector(assets, out_dir)
            inspected = sum(1 for a in assets if a.get("web_inspection"))
            print(f"  [✓] Web inspection complete for {inspected} asset(s)")
        except Exception as e:
            print(f"  [✗] Web inspection failed: {e}")
    elif args.web_inspect and domain_targets:
        print_phase_header("Web Application Inspection (inSp3ctor)")
        try:
            from recon.web import run_web_inspector
            web_assets = [
                {
                    "source": "domain_target",
                    "hostname": domain,
                    "fqdn": domain,
                    "domain": domain,
                    "ports": [],
                    "services": ["http", "https"],
                }
                for domain in domain_targets
            ]
            assets.extend(run_web_inspector(web_assets, out_dir))
            inspected = sum(1 for a in assets if a.get("web_inspection"))
            print(f"  [✓] Web inspection complete for {inspected} asset(s)")
        except Exception as e:
            print(f"  [✗] Web inspection failed: {e}")

    # ── Hunter.how ─────────────────────────────────────────────
    if args.hunter and assets:
        print_phase_header("Email / Personnel OSINT (Hunter.how)")
        try:
            from recon.hunter_recon import run_hunter
            assets = run_hunter(assets, out_dir)
            found = sum(1 for a in assets if a.get("hunter_findings"))
            print(f"  [✓] Hunter.how findings for {found} asset(s)")
        except Exception as e:
            print(f"  [✗] Hunter.how recon failed: {e}")

    # ── Topology ──────────────────────────────────────────────
    if args.topology and assets:
        print_phase_header("Topology Mapping")
        try:
            from core.topology import map_topology
            map_topology(assets, out_dir)
            print(f"  [✓] Topology map saved to {out_dir}")
        except Exception as e:
            print(f"  [✗] Topology failed: {e}")

    # ── Compliance ────────────────────────────────────────────
    compliance_results = None
    if args.compliance and assets:
        print_phase_header("CIS Controls Compliance")
        try:
            from analysis.compliance import check_compliance, generate_compliance_report
            compliance_results = check_compliance(assets)
            score = compliance_results.get("overall_score", 0)
            print(f"  [✓] Overall compliance score: {score:.1f}/100")
            compliance_path = out_dir / f"compliance_{timestamp}.txt"
            compliance_path.write_text(generate_compliance_report(compliance_results))
            print(f"  [✓] Compliance report: {compliance_path}")
        except Exception as e:
            print(f"  [✗] Compliance check failed: {e}")

    # ── History tracking ──────────────────────────────────────
    if args.history and assets:
        print_phase_header("History Tracking")
        try:
            from recon.asset import initialize_database, record_scan
            db_path = Path.home() / ".inventa" / "history.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)
            initialize_database(db_path)
            duration = time.time() - start_time
            scan_id = record_scan(assets, db_path, args.profile, duration)
            print(f"  [✓] Scan #{scan_id} recorded to history DB")
        except Exception as e:
            print(f"  [✗] History tracking failed: {e}")

    # ── Save JSON ─────────────────────────────────────────────
    json_path = out_dir / f"inventa_data_{timestamp}.json"
    json_path.write_text(json.dumps(assets, indent=2, default=str))
    print(f"\n  [✓] JSON data: {json_path}")

    # ── Reports ───────────────────────────────────────────────
    if args.report in ("html", "both"):
        print_phase_header("Report Generation")
        try:
            from reporting.reporter import generate_html_report
            html_path = out_dir / f"inventa_report_{timestamp}.html"
            generate_html_report(assets, html_path)
            print(f"  [✓] HTML report: {html_path}")
        except Exception as e:
            print(f"  [✗] HTML report failed: {e}")

    if args.report in ("csv", "both"):
        try:
            from reporting.reporter import generate_csv_report
            csv_path = out_dir / f"inventa_report_{timestamp}.csv"
            generate_csv_report(assets, csv_path)
            print(f"  [✓] CSV report: {csv_path}")
        except Exception as e:
            print(f"  [✗] CSV report failed: {e}")

    # ── Summary ───────────────────────────────────────────────
    print_scan_summary(assets)
    duration = time.time() - start_time
    print(f"  Scan completed in {duration:.1f}s\n")


# ── Entry point ───────────────────────────────────────────────

def main():
    load_env()
    if len(sys.argv) == 1:
        interactive_mode()
    else:
        args = parse_args()
        if args.examples:
            print_examples()
            return
        if args.list_workflows:
            print_workflows()
            return
        if args.results:
            browse_results_interactive(Path(args.out))
            return
        if args.doctor:
            from core.doctor import run_doctor

            raise SystemExit(run_doctor(args.out))
        run_inventa(args)


if __name__ == "__main__":
    main()
