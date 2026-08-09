"""
Subdomain Enumeration Module
Discovers subdomains using all three tools in combination:

  • Amass       https://github.com/owasp-amass/amass
  • Subfinder   https://github.com/projectdiscovery/subfinder
  • AssetFinder https://github.com/tomnomnom/assetfinder

Each tool runs independently against every domain target.  Results are
deduplicated across all three, resolved to IP addresses via DNS, filtered
by the authorised scope CIDRs, and returned as Inventa asset dicts.

A tool that is not installed is silently skipped — the other two still run.
At least one tool must be present for any results to be produced.

Tool detection order (per tool):
  1. System PATH
  2. tools/<toolname>/<toolname> binary  (placed by install.sh)
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set

import dns.resolver


# ── Public entry point ────────────────────────────────────────────────────────

def run_subdomain_enum(
    targets: List[str],
    assets: List[Dict],
    scope_cidrs,
    out_dir: Path,
) -> List[Dict]:
    """
    Run Amass, Subfinder, and AssetFinder against every domain found in
    *targets* and *assets*.  Returns new asset dicts (one per resolved IP).
    Does not mutate the existing asset list.
    """
    domains = _collect_domains(targets, assets)
    if not domains:
        print("  [!] No domain targets found for subdomain enumeration")
        return []

    available = _tools_available()
    if not available:
        print("  [!] No subdomain tools found (amass / subfinder / assetfinder)")
        print("      Run install.sh or install them manually and ensure they are in PATH")
        return []

    print(f"  [*] Tools available: {', '.join(available)}")
    print(f"  [*] Enumerating subdomains for: {', '.join(sorted(domains))}")

    discovered: Set[str] = set()

    for domain in sorted(domains):
        amass_subs       = _run_amass(domain, out_dir)
        subfinder_subs   = _run_subfinder(domain, out_dir)
        assetfinder_subs = _run_assetfinder(domain, out_dir)

        combined = amass_subs | subfinder_subs | assetfinder_subs
        if combined:
            parts = []
            if amass_subs:       parts.append(f"{len(amass_subs)} amass")
            if subfinder_subs:   parts.append(f"{len(subfinder_subs)} subfinder")
            if assetfinder_subs: parts.append(f"{len(assetfinder_subs)} assetfinder")
            print(f"  [+] {domain} — {' + '.join(parts)} = {len(combined)} unique subdomain(s)")
        else:
            print(f"  [-] {domain} — no subdomains found")

        discovered.update(combined)

    if not discovered:
        print("  [!] No subdomains discovered across all tools")
        return []

    print(f"  [*] Resolving {len(discovered)} unique subdomain(s)...")
    return _resolve_and_filter(discovered, scope_cidrs, available)


# ── Amass wrapper ─────────────────────────────────────────────────────────────

def _run_amass(domain: str, out_dir: Path) -> Set[str]:
    binary = _find_binary("amass", "amass")
    if not binary:
        return set()

    out_file = out_dir / f"amass_{domain}.txt"
    cmd = [binary, "enum", "-passive", "-d", domain, "-o", str(out_file), "-nocolor"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        subdomains: Set[str] = set()

        # Primary: output file
        if out_file.exists():
            for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                sub = line.strip().lower()
                if sub and _looks_like_domain(sub) and (sub.endswith(f".{domain}") or sub == domain):
                    subdomains.add(sub)

        # Fallback: stdout (some amass versions write there instead)
        for line in result.stdout.splitlines():
            sub = line.strip().lower()
            if sub and _looks_like_domain(sub) and (sub.endswith(f".{domain}") or sub == domain):
                subdomains.add(sub)

        return subdomains

    except subprocess.TimeoutExpired:
        print(f"  [!] amass timed out for {domain}")
        return set()
    except Exception as e:
        print(f"  [!] amass error for {domain}: {e}")
        return set()


# ── Subfinder wrapper ─────────────────────────────────────────────────────────

def _run_subfinder(domain: str, out_dir: Path) -> Set[str]:
    binary = _find_binary("subfinder", "subfinder")
    if not binary:
        return set()

    out_file = out_dir / f"subfinder_{domain}.txt"
    cmd = [binary, "-d", domain, "-o", str(out_file), "-silent"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        subdomains: Set[str] = set()

        if out_file.exists():
            for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                sub = line.strip().lower()
                if sub and _looks_like_domain(sub) and (sub.endswith(f".{domain}") or sub == domain):
                    subdomains.add(sub)

        for line in result.stdout.splitlines():
            sub = line.strip().lower()
            if sub and _looks_like_domain(sub) and (sub.endswith(f".{domain}") or sub == domain):
                subdomains.add(sub)

        return subdomains

    except subprocess.TimeoutExpired:
        print(f"  [!] subfinder timed out for {domain}")
        return set()
    except Exception as e:
        print(f"  [!] subfinder error for {domain}: {e}")
        return set()


# ── AssetFinder wrapper ───────────────────────────────────────────────────────

def _run_assetfinder(domain: str, out_dir: Path) -> Set[str]:
    """
    AssetFinder writes only to stdout (no -o flag), so output is captured from
    the subprocess and also saved to a file for the audit trail.
    """
    binary = _find_binary("assetfinder", "assetfinder")
    if not binary:
        return set()

    out_file = out_dir / f"assetfinder_{domain}.txt"
    cmd = [binary, "--subs-only", domain]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        subdomains: Set[str] = set()

        for line in result.stdout.splitlines():
            sub = line.strip().lower()
            if sub and _looks_like_domain(sub) and (sub.endswith(f".{domain}") or sub == domain):
                subdomains.add(sub)

        # Persist for audit trail
        if subdomains:
            out_file.write_text("\n".join(sorted(subdomains)), encoding="utf-8")

        return subdomains

    except subprocess.TimeoutExpired:
        print(f"  [!] assetfinder timed out for {domain}")
        return set()
    except Exception as e:
        print(f"  [!] assetfinder error for {domain}: {e}")
        return set()


# ── Resolution + scope filtering ──────────────────────────────────────────────

def _resolve_and_filter(
    subdomains: Set[str],
    scope_cidrs,
    tools_used: List[str],
) -> List[Dict]:
    new_assets: List[Dict] = []

    with ThreadPoolExecutor(max_workers=30) as executor:
        future_to_sub = {executor.submit(_resolve, sub): sub for sub in subdomains}
        for future in as_completed(future_to_sub):
            subdomain = future_to_sub[future]
            try:
                ips = future.result()
                for ip in ips:
                    if _in_scope(ip, scope_cidrs):
                        new_assets.append({
                            "source": "subdomain_enum",
                            "hostname": subdomain,
                            "ip": ip,
                            "ports": [],
                            "services": [],
                            "subdomain_enum_tools": tools_used,
                        })
            except Exception:
                pass

    return new_assets


def _resolve(hostname: str) -> List[str]:
    ips: List[str] = []
    try:
        for rdata in dns.resolver.resolve(hostname, "A", lifetime=5):
            ips.append(str(rdata))
    except Exception:
        pass
    return ips


# ── Helpers ───────────────────────────────────────────────────────────────────

def _collect_domains(targets: List[str], assets: List[Dict]) -> Set[str]:
    domains: Set[str] = set()
    for t in targets:
        t = t.strip()
        if _looks_like_domain(t) and not _is_ip_or_cidr(t):
            domains.add(t.lstrip("*.").lower())
    for a in assets:
        for key in ("hostname", "fqdn", "domain"):
            val = a.get(key)
            if val and _looks_like_domain(str(val)) and not _is_ip_or_cidr(str(val)):
                domains.add(str(val).lower())
    return domains


def _find_binary(name: str, subdir: str) -> Optional[str]:
    if shutil.which(name):
        return name
    local = Path(__file__).parent.parent / "tools" / subdir / name
    if local.exists() and local.is_file():
        return str(local)
    return None


def _tools_available() -> List[str]:
    return [
        name for name in ("amass", "subfinder", "assetfinder")
        if _find_binary(name, name)
    ]


def _looks_like_domain(val: str) -> bool:
    return "." in val and " " not in val and not val.startswith("-")


def _is_ip_or_cidr(val: str) -> bool:
    try:
        ipaddress.ip_network(val, strict=False)
        return True
    except ValueError:
        return False


def _in_scope(ip: str, scope_cidrs) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in scope_cidrs:
            try:
                if addr in ipaddress.ip_network(str(cidr), strict=False):
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False
