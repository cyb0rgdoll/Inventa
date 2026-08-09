"""
Domain Recon Module
Integrated domain reconnaissance workflow using:

  - subfinder
  - assetfinder
  - amass
  - httpx
  - nmap
  - nuclei

Results are stored under the current scan output directory instead of ~/recon.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

from modules.active_scan import parse_nmap_xml


def run_domain_recon(domains: Iterable[str], out_dir: Path) -> List[Dict]:
    domain_list = sorted({str(d).strip().lower() for d in domains if str(d).strip()})
    if not domain_list:
        print("  [!] No domain targets supplied for domain recon")
        return []

    recon_root = out_dir / "domain_recon"
    recon_root.mkdir(parents=True, exist_ok=True)

    all_assets: List[Dict] = []
    for domain in domain_list:
        print(f"  [*] Domain recon: {domain}")
        domain_dir = recon_root / domain.replace("/", "_")
        domain_dir.mkdir(parents=True, exist_ok=True)

        subdomains = _enumerate_subdomains(domain, domain_dir)
        if not subdomains:
            print(f"  [!] No subdomains found for {domain}")
            continue

        live_hosts = _probe_live_hosts(subdomains, domain_dir)
        if not live_hosts:
            print(f"  [!] No live hosts found for {domain}")
            continue

        tech_by_url = _detect_web_technologies(live_hosts, domain_dir)
        nuclei_by_url = _run_nuclei(live_hosts, domain_dir)
        nmap_assets = _run_nmap_on_hosts(live_hosts, domain_dir)

        merged_assets = _merge_recon_results(domain, live_hosts, tech_by_url, nuclei_by_url, nmap_assets)
        all_assets.extend(merged_assets)

    return all_assets


def _enumerate_subdomains(domain: str, domain_dir: Path) -> List[str]:
    results: Set[str] = set()

    subfinder = _find_binary("subfinder")
    if subfinder:
        out_file = domain_dir / "subdomains_subfinder.txt"
        _run_command([subfinder, "-d", domain, "-silent", "-o", str(out_file)], timeout=180)
        results.update(_read_lines(out_file))

    assetfinder = _find_binary("assetfinder")
    if assetfinder:
        out_file = domain_dir / "subdomains_assetfinder.txt"
        stdout = _run_command([assetfinder, "--subs-only", domain], timeout=120)
        if stdout:
            out_file.write_text(stdout, encoding="utf-8")
            results.update(_normalize_domains(stdout.splitlines(), domain))

    amass = _find_binary("amass")
    if amass:
        out_file = domain_dir / "subdomains_amass.txt"
        _run_command([amass, "enum", "-passive", "-d", domain, "-o", str(out_file), "-nocolor"], timeout=300)
        results.update(_read_lines(out_file))

    combined = sorted(_normalize_domains(results, domain))
    (domain_dir / "subdomains.txt").write_text("\n".join(combined), encoding="utf-8")
    return combined


def _probe_live_hosts(subdomains: List[str], domain_dir: Path) -> List[Dict]:
    httpx = _find_binary("httpx")
    if not httpx:
        print("  [!] httpx not found — skipping live host probing")
        return []

    input_file = domain_dir / "subdomains.txt"
    output_file = domain_dir / "live_hosts.jsonl"
    _run_command(
        [httpx, "-silent", "-json", "-l", str(input_file), "-o", str(output_file)],
        timeout=300,
    )

    live_hosts = []
    for line in _read_lines(output_file):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = row.get("url")
        host = row.get("host")
        port = row.get("port")
        scheme = row.get("scheme")
        if not url or not host:
            continue
        live_hosts.append({
            "url": url,
            "host": host,
            "port": port,
            "scheme": scheme,
        })
    return live_hosts


def _detect_web_technologies(live_hosts: List[Dict], domain_dir: Path) -> Dict[str, List[str]]:
    httpx = _find_binary("httpx")
    if not httpx or not live_hosts:
        return {}

    input_file = domain_dir / "live_hosts_urls.txt"
    output_file = domain_dir / "technologies.jsonl"
    input_file.write_text("\n".join(sorted({h["url"] for h in live_hosts})), encoding="utf-8")

    _run_command(
        [httpx, "-silent", "-json", "-tech-detect", "-l", str(input_file), "-o", str(output_file)],
        timeout=300,
    )

    tech_by_url: Dict[str, List[str]] = {}
    for line in _read_lines(output_file):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = row.get("url")
        tech = row.get("tech") or []
        if url:
            tech_by_url[url] = [str(t) for t in tech if t]
    return tech_by_url


def _run_nuclei(live_hosts: List[Dict], domain_dir: Path) -> Dict[str, List[Dict]]:
    nuclei = _find_binary("nuclei")
    if not nuclei or not live_hosts:
        return {}

    input_file = domain_dir / "live_hosts_urls.txt"
    output_file = domain_dir / "nuclei_results.jsonl"
    if not input_file.exists():
        input_file.write_text("\n".join(sorted({h["url"] for h in live_hosts})), encoding="utf-8")

    _run_command(
        [nuclei, "-l", str(input_file), "-jsonl", "-o", str(output_file)],
        timeout=600,
    )

    findings_by_url: Dict[str, List[Dict]] = {}
    for line in _read_lines(output_file):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        matched = row.get("matched-at") or row.get("host")
        if not matched:
            continue
        findings_by_url.setdefault(matched, []).append({
            "template_id": row.get("template-id"),
            "info": row.get("info") or {},
            "severity": (row.get("info") or {}).get("severity"),
            "matcher_name": row.get("matcher-name"),
            "type": row.get("type"),
        })
    return findings_by_url


def _run_nmap_on_hosts(live_hosts: List[Dict], domain_dir: Path) -> List[Dict]:
    nmap = _find_binary("nmap")
    if not nmap or not live_hosts:
        return []

    host_targets = sorted({h["host"] for h in live_hosts if h.get("host")})
    if not host_targets:
        return []

    hosts_file = domain_dir / "nmap_hosts.txt"
    xml_file = domain_dir / "nmap_scan.xml"
    hosts_file.write_text("\n".join(host_targets), encoding="utf-8")

    _run_command(
        [nmap, "-iL", str(hosts_file), "-sV", "-oX", str(xml_file)],
        timeout=600,
    )
    if not xml_file.exists():
        return []
    return parse_nmap_xml(xml_file)


def _merge_recon_results(
    domain: str,
    live_hosts: List[Dict],
    tech_by_url: Dict[str, List[str]],
    nuclei_by_url: Dict[str, List[Dict]],
    nmap_assets: List[Dict],
) -> List[Dict]:
    assets_by_host: Dict[str, Dict] = {}

    nmap_by_host = {}
    for asset in nmap_assets:
        host_key = asset.get("hostname") or asset.get("ip")
        if host_key:
            nmap_by_host[host_key] = asset
            if asset.get("ip"):
                nmap_by_host[asset["ip"]] = asset

    for host in live_hosts:
        hostname = host.get("host")
        url = host.get("url")
        parsed = urlparse(url)
        key = hostname
        nmap_asset = nmap_by_host.get(hostname)

        asset = assets_by_host.setdefault(key, {
            "source": "domain_recon",
            "hostname": hostname,
            "fqdn": hostname,
            "domain": domain,
            "ip": (nmap_asset or {}).get("ip"),
            "ports": list((nmap_asset or {}).get("ports", [])),
            "services": list((nmap_asset or {}).get("services", [])),
            "vulnerabilities": list((nmap_asset or {}).get("vulnerabilities", [])),
            "domain_recon": {
                "urls": [],
                "technologies": {},
                "nuclei_findings": {},
            },
        })

        if url not in asset["domain_recon"]["urls"]:
            asset["domain_recon"]["urls"].append(url)
        asset["endpoint"] = url

        if url in tech_by_url:
            asset["domain_recon"]["technologies"][url] = tech_by_url[url]
            for tech in tech_by_url[url]:
                if tech not in asset["services"]:
                    asset["services"].append(tech)

        findings = nuclei_by_url.get(url) or nuclei_by_url.get(hostname) or []
        if findings:
            asset["domain_recon"]["nuclei_findings"][url] = findings
            for finding in findings:
                severity = finding.get("severity")
                template_id = finding.get("template_id")
                if template_id:
                    asset["vulnerabilities"].append({
                        "cve_id": template_id,
                        "summary": template_id,
                        "cvss": None,
                        "severity": severity,
                        "published": None,
                        "source": "nuclei",
                        "port": str(parsed.port or (443 if parsed.scheme == "https" else 80)),
                    })

    return list(assets_by_host.values())


def _find_binary(name: str) -> Optional[str]:
    if shutil.which(name):
        return name
    local = Path(__file__).parent.parent / "tools" / name / name
    if local.exists():
        return str(local)
    return None


def _run_command(cmd: List[str], timeout: int) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0 and result.stderr.strip():
            print(f"  [!] {' '.join(cmd[:2])} exited with {result.returncode}: {result.stderr.strip()[:200]}")
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"  [!] Command timed out: {' '.join(cmd[:2])}")
        return ""
    except Exception as e:
        print(f"  [!] Command failed: {' '.join(cmd[:2])}: {e}")
        return ""


def _read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]


def _normalize_domains(values: Iterable[str], parent_domain: str) -> Set[str]:
    result = set()
    for value in values:
        sub = str(value).strip().lower()
        if sub and (sub == parent_domain or sub.endswith(f".{parent_domain}")):
            result.add(sub)
    return result
