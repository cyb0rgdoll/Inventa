"""
Cloud Scraper Recon Module
Discovers cloud-hosted assets by spidering domains and inspecting DNS records.
Inspired by CloudScraper (https://github.com/jordanpotti/CloudScraper)

Runs the real CloudScraper CLI automatically if cloned into tools/CloudScraper/.
Falls back to a native Python implementation otherwise.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from modules.platform_compat import python_executable


# ── Cloud provider URL / CNAME fingerprints ──────────────────────────────────

CLOUD_PATTERNS: Dict[str, List[str]] = {
    "aws_s3":              [r"s3\.amazonaws\.com", r"s3-website", r"s3-[a-z0-9-]+\.amazonaws\.com"],
    "aws_cloudfront":      [r"cloudfront\.net"],
    "aws_elasticbeanstalk":[r"elasticbeanstalk\.com"],
    "aws_ec2":             [r"compute\.amazonaws\.com", r"ec2\.amazonaws\.com"],
    "aws_lambda":          [r"lambda-url\.[a-z0-9-]+\.on\.aws"],
    "aws_general":         [r"amazonaws\.com"],
    "azure_blob":          [r"blob\.core\.windows\.net"],
    "azure_web":           [r"azurewebsites\.net"],
    "azure_cdn":           [r"azureedge\.net", r"azurefd\.net"],
    "azure_cloudapp":      [r"cloudapp\.azure\.com", r"cloudapp\.net"],
    "azure_onmicrosoft":   [r"onmicrosoft\.com"],
    "gcp_storage":         [r"storage\.googleapis\.com"],
    "gcp_appengine":       [r"appspot\.com"],
    "gcp_run":             [r"run\.app"],
    "gcp_cloudfunctions":  [r"cloudfunctions\.net"],
    "gcp_content":         [r"googleusercontent\.com"],
    "heroku":              [r"herokuapp\.com"],
    "digitalocean":        [r"digitaloceanspaces\.com"],
    "cloudflare_workers":  [r"workers\.dev"],
    "cloudflare_pages":    [r"pages\.dev"],
    "netlify":             [r"netlify\.app", r"netlify\.com"],
    "vercel":              [r"vercel\.app", r"now\.sh"],
    "github_pages":        [r"github\.io"],
    "fastly":              [r"fastly\.net"],
    "akamai":              [r"akamaiedge\.net", r"akamaized\.net"],
}

_COMPILED: Dict[str, re.Pattern] = {
    provider: re.compile("|".join(patterns), re.IGNORECASE)
    for provider, patterns in CLOUD_PATTERNS.items()
}

REQUEST_TIMEOUT = 10
MAX_PAGES_PER_DOMAIN = 20


# ── Public entry point ────────────────────────────────────────────────────────

def run_cloud_scraper(assets: List[Dict], out_dir: Path) -> List[Dict]:
    """
    Enrich assets with cloud resource indicators found by spidering their domains.
    Writes 'cloud_scraper_findings' into each relevant asset dict.
    """
    _try_external_tool(assets, out_dir)

    session = requests.Session()
    session.headers.update({"User-Agent": "Inventa/2.0 CloudScraperRecon"})

    for asset in assets:
        domain = _get_domain(asset)
        if not domain:
            continue

        findings = scrape_domain(domain, session)
        if findings:
            asset["cloud_scraper_findings"] = findings
            providers = sorted({f["provider"] for f in findings})
            print(f"  [+] {domain} — {len(findings)} cloud indicator(s): {', '.join(providers)}")

    return assets


# ── Core scraper ──────────────────────────────────────────────────────────────

def scrape_domain(domain: str, session: requests.Session) -> List[Dict]:
    findings: List[Dict] = []
    visited: Set[str] = set()
    queue: List[str] = [f"https://{domain}", f"http://{domain}"]
    crawled = 0

    while queue and crawled < MAX_PAGES_PER_DOMAIN:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        crawled += 1

        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)

            findings.extend(_check_string(url))
            for r in resp.history:
                findings.extend(_check_string(r.url))

            if "text/html" in resp.headers.get("Content-Type", ""):
                soup = BeautifulSoup(resp.text, "html.parser")
                for tag in soup.find_all(href=True):
                    href = urljoin(url, tag["href"])
                    findings.extend(_check_string(href))
                    if urlparse(href).netloc == domain and href not in visited:
                        queue.append(href)
                for tag in soup.find_all(src=True):
                    src = urljoin(url, tag["src"])
                    findings.extend(_check_string(src))

            for val in resp.headers.values():
                findings.extend(_check_string(val))

        except requests.exceptions.RequestException:
            pass

    findings.extend(_check_dns(domain))
    return _dedupe_findings(findings)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_string(text: str) -> List[Dict]:
    hits = []
    for provider, pattern in _COMPILED.items():
        if pattern.search(text):
            hits.append({
                "provider": provider,
                "indicator": "url_or_header",
                "value": text[:300],
                "cloud_provider": _map_provider(provider),
            })
    return hits


def _check_dns(domain: str) -> List[Dict]:
    findings = []
    try:
        import dns.resolver
        for rtype in ("CNAME", "A", "MX", "NS"):
            try:
                for rdata in dns.resolver.resolve(domain, rtype, lifetime=5):
                    val = str(rdata)
                    for provider, pattern in _COMPILED.items():
                        if pattern.search(val):
                            findings.append({
                                "provider": provider,
                                "indicator": f"dns_{rtype.lower()}",
                                "value": val,
                                "cloud_provider": _map_provider(provider),
                            })
            except Exception:
                continue
    except ImportError:
        pass
    return findings


def _try_external_tool(assets: List[Dict], out_dir: Path) -> None:
    tool_path = Path(__file__).parent.parent / "tools" / "CloudScraper" / "CloudScraper.py"
    if not tool_path.exists():
        return

    domains = [d for d in (_get_domain(a) for a in assets) if d]
    if not domains:
        return

    targets_file = out_dir / "cloudscraper_targets.txt"
    targets_file.write_text("\n".join(domains), encoding="utf-8")
    out_file = out_dir / "cloudscraper_raw.txt"

    try:
        result = subprocess.run(
            [python_executable(), str(tool_path), "-l", str(targets_file), "-d", "3"],
            capture_output=True, text=True, timeout=120,
        )
        raw_output = (result.stdout or "").strip()
        if result.stderr:
            raw_output = f"{raw_output}\n{result.stderr.strip()}".strip()
        out_file.write_text(raw_output + ("\n" if raw_output else ""), encoding="utf-8")
        print(f"  [✓] CloudScraper (external) raw output: {out_file}")
    except Exception:
        pass


def _get_domain(asset: Dict) -> Optional[str]:
    for key in ("hostname", "fqdn", "endpoint", "domain"):
        val = asset.get(key)
        if val and "." in str(val) and not _is_ip(str(val)):
            return str(val).strip().lower()
    return None


def _is_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


def _map_provider(provider: str) -> str:
    if provider.startswith("aws"):
        return "AWS"
    if provider.startswith("azure"):
        return "Azure"
    if provider.startswith("gcp"):
        return "GCP"
    return provider.replace("_", " ").title()


def _dedupe_findings(findings: List[Dict]) -> List[Dict]:
    seen: Set[tuple] = set()
    result = []
    for f in findings:
        key = (f["provider"], f["value"])
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result
