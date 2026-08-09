"""
OSINT / External Exposure / Vulnerability Intel module for Inventa.

Defensive enrichment only:
- public IPs
- public domains/FQDNs
- CVE enrichment for already-identified CVE IDs

Providers supported:
  IP:
    - Shodan
    - Censys
    - VirusTotal
    - IPinfo
    - BGPView
    - Netlas
    - FullHunt
  Domain:
    - VirusTotal
    - SecurityTrails
    - Host.io
    - DomainsDB
    - Cloudflare trace (best-effort probe)
    - Netlas
    - IntelX
    - FullHunt
  Vulnerability:
    - NVD
    - OpenCVE
    - KEVin
    - Vulners
    - VulDB

Environment variables:
  SHODAN_API_KEY
  CENSYS_API_ID
  CENSYS_API_SECRET
  VIRUSTOTAL_API_KEY
  SECURITYTRAILS_API_KEY
  HOSTIO_API_KEY
  BUILTWITH_API_KEY
  DOMAINSDB_API_KEY              # optional, adapter will also try unauthenticated if supported
  NETLAS_API_KEY
  INTELX_API_KEY
  FULLHUNT_API_KEY
  IPINFO_API_KEY
  NVD_API_KEY                    # optional
  OPENCVE_TOKEN                  # preferred if available
  OPENCVE_USERNAME               # optional basic auth fallback
  OPENCVE_PASSWORD               # optional basic auth fallback
  VULNERS_API_KEY
  VULDB_API_KEY
  INVENTA_OSINT_CACHE_DIR        # optional
  INVENTA_OSINT_CACHE_TTL        # optional, seconds, default 43200
  INVENTA_OSINT_TIMEOUT          # optional, seconds, default 15
  INVENTA_OSINT_SKIP_PROVIDERS   # optional comma list, e.g. shodan,censys,bgpview
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import quote

import requests


CACHE_TTL_SECONDS = int(os.environ.get("INVENTA_OSINT_CACHE_TTL", "43200"))
REQUEST_TIMEOUT = int(os.environ.get("INVENTA_OSINT_TIMEOUT", "15"))
CACHE_DIR = Path(
    os.environ.get(
        "INVENTA_OSINT_CACHE_DIR",
        str(Path.home() / ".inventa" / "osint_cache"),
    )
)
_UNAVAILABLE_PROVIDERS: Set[str] = set()


def osint_lookup(assets: List[Dict]) -> List[Dict]:
    """
    Enrich assets with external exposure and vulnerability intelligence.

    Writes:
      asset["osint_exposure"]
      asset["externally_exposed"]
      asset["exposure_score"]
      asset["vulnerability_intel"]   (if CVE enrichment was possible)
    """
    config = load_provider_config()

    if not any(config.values()):
        print("  [!] No OSINT or vulnerability-intel API keys configured - skipping enrichment")
        print("  [i] Configure provider keys via environment variables")
        return assets

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    session.headers.update({"User-Agent": "Inventa/2.0"})

    for asset in assets:
        public_ip = get_public_ip_for_osint(asset)
        domains = get_public_domains_for_osint(asset)
        cve_ids = extract_cve_ids(asset)

        provider_hits: List[Dict[str, Any]] = []
        vuln_hits: List[Dict[str, Any]] = []

        if public_ip:
            provider_hits.extend(query_ip_providers(public_ip, config, session))

        for domain in domains:
            provider_hits.extend(query_domain_providers(domain, config, session, asset))

        for cve_id in cve_ids:
            vuln_hits.extend(query_vulnerability_providers(cve_id, config, session))

        if provider_hits:
            merged = merge_provider_hits(provider_hits)
            asset["osint_exposure"] = merged
            asset["externally_exposed"] = merged["summary"]["provider_count"] > 0
            asset["exposure_score"] = score_exposure(merged)

            print(
                f"  [+] {asset.get('ip') or asset.get('public_ip') or asset.get('hostname')} "
                f"- {merged['summary']['provider_count']} exposure provider(s) matched"
            )

        if vuln_hits:
            asset["vulnerability_intel"] = merge_vulnerability_hits(vuln_hits)
            print(
                f"  [+] {asset.get('ip') or asset.get('hostname') or 'asset'} "
                f"- vulnerability intel for {len(asset['vulnerability_intel'])} CVE(s)"
            )

    return assets


# ---------------------------------------------------------------------------
# Provider config / routing
# ---------------------------------------------------------------------------

def load_provider_config() -> Dict[str, Optional[str]]:
    config = {
        "shodan": os.environ.get("SHODAN_API_KEY"),
        "censys_id": os.environ.get("CENSYS_API_ID"),
        "censys_secret": os.environ.get("CENSYS_API_SECRET"),
        "virustotal": os.environ.get("VIRUSTOTAL_API_KEY"),
        "ipinfo": os.environ.get("IPINFO_API_KEY"),
        "securitytrails": os.environ.get("SECURITYTRAILS_API_KEY"),
        "hostio": os.environ.get("HOSTIO_API_KEY"),
        "builtwith": os.environ.get("BUILTWITH_API_KEY"),
        "domainsdb": os.environ.get("DOMAINSDB_API_KEY"),
        "nvd": os.environ.get("NVD_API_KEY"),
        "opencve_token": os.environ.get("OPENCVE_TOKEN"),
        "opencve_username": os.environ.get("OPENCVE_USERNAME"),
        "opencve_password": os.environ.get("OPENCVE_PASSWORD"),
        "vulners": os.environ.get("VULNERS_API_KEY"),
        "vuldb": os.environ.get("VULDB_API_KEY"),
        "netlas": os.environ.get("NETLAS_API_KEY"),
        "intelx": os.environ.get("INTELX_API_KEY"),
        "fullhunt": os.environ.get("FULLHUNT_API_KEY"),
        # BGPView + KEVin + Cloudflare trace do not require keys here
        "bgpview": "enabled",
        "kevin": "enabled",
        "cloudflare_trace": "enabled",
    }
    for provider in _skip_providers():
        if provider == "censys":
            config["censys_id"] = None
            config["censys_secret"] = None
        elif provider in config:
            config[provider] = None
    return config


def query_ip_providers(ip: str, config: Dict[str, Optional[str]], session: requests.Session) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []

    if config.get("shodan"):
        hit = query_shodan_ip(ip, config["shodan"], session)
        if hit:
            hits.append(hit)

    if config.get("censys_id") and config.get("censys_secret"):
        hit = query_censys_ip(ip, config["censys_id"], config["censys_secret"], session)
        if hit:
            hits.append(hit)

    if config.get("virustotal"):
        hit = query_virustotal_ip(ip, config["virustotal"], session)
        if hit:
            hits.append(hit)

    if config.get("ipinfo"):
        hit = query_ipinfo_ip(ip, config["ipinfo"], session)
        if hit:
            hits.append(hit)

    if config.get("bgpview"):
        hit = query_bgpview_ip(ip, session)
        if hit:
            hits.append(hit)

    if config.get("netlas"):
        hit = query_netlas_ip(ip, config["netlas"], session)
        if hit:
            hits.append(hit)

    if config.get("fullhunt"):
        hit = query_fullhunt_ip(ip, config["fullhunt"], session)
        if hit:
            hits.append(hit)

    return hits


def query_domain_providers(
    domain: str,
    config: Dict[str, Optional[str]],
    session: requests.Session,
    asset: Dict[str, Any],
) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []

    if config.get("virustotal"):
        hit = query_virustotal_domain(domain, config["virustotal"], session)
        if hit:
            hits.append(hit)

    if config.get("securitytrails"):
        hit = query_securitytrails_domain(domain, config["securitytrails"], session)
        if hit:
            hits.append(hit)

    if config.get("hostio"):
        hit = query_hostio_domain(domain, config["hostio"], session)
        if hit:
            hits.append(hit)

    if config.get("builtwith"):
        hit = query_builtwith_domain(domain, config["builtwith"], session)
        if hit:
            hits.append(hit)

    # best-effort: can work with or without auth depending on service policy / plan
    if config.get("domainsdb") is not None or "domainsdb" not in _skip_providers():
        hit = query_domainsdb_domain(domain, config.get("domainsdb"), session)
        if hit:
            hits.append(hit)

    # only probe Cloudflare trace on likely web assets
    if config.get("cloudflare_trace") and is_likely_web_asset(asset):
        hit = query_cloudflare_trace(domain, session)
        if hit:
            hits.append(hit)

    if config.get("netlas"):
        hit = query_netlas_domain(domain, config["netlas"], session)
        if hit:
            hits.append(hit)

    if config.get("intelx"):
        hit = query_intelx_domain(domain, config["intelx"], session)
        if hit:
            hits.append(hit)

    if config.get("fullhunt"):
        hit = query_fullhunt_domain(domain, config["fullhunt"], session)
        if hit:
            hits.append(hit)

    return hits


def query_vulnerability_providers(
    cve_id: str,
    config: Dict[str, Optional[str]],
    session: requests.Session,
) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []

    if config.get("kevin"):
        hit = query_kevin_cve(cve_id, session)
        if hit:
            hits.append(hit)

    hit = query_nvd_cve(cve_id, config.get("nvd"), session)
    if hit:
        hits.append(hit)

    hit = query_opencve_cve(
        cve_id,
        config.get("opencve_token"),
        config.get("opencve_username"),
        config.get("opencve_password"),
        session,
    )
    if hit:
        hits.append(hit)

    if config.get("vulners"):
        hit = query_vulners_cve(cve_id, config["vulners"], session)
        if hit:
            hits.append(hit)

    if config.get("vuldb"):
        hit = query_vuldb_cve(cve_id, config["vuldb"], session)
        if hit:
            hits.append(hit)

    return hits


# ---------------------------------------------------------------------------
# IP exposure providers
# ---------------------------------------------------------------------------

def query_shodan_ip(ip: str, api_key: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"shodan:ip:{ip}"

    def fetch():
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        response = session.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code in (401, 403):
            _mark_provider_unavailable("shodan", "invalid or unauthorized API key")
            return None
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()

        services = []
        for item in data.get("data", []) or []:
            service_name = item.get("_shodan", {}).get("module") or item.get("product") or item.get("transport")
            if service_name:
                services.append(str(service_name))

        vulns = data.get("vulns") or []
        if isinstance(vulns, dict):
            vulns = list(vulns.keys())

        return normalize_exposure_hit(
            provider="shodan",
            target_type="ip",
            target=ip,
            open_ports=safe_int_list(data.get("ports", [])),
            hostnames=data.get("hostnames", []) or [],
            services=dedupe_list(services),
            organization=data.get("org"),
            asn=data.get("asn"),
            country=data.get("country_name"),
            vulnerabilities=dedupe_list(vulns),
            last_seen=data.get("last_update"),
            tags=data.get("tags", []) or [],
            confidence=0.90,
            raw=data,
        )

    return cached_fetch(cache_key, fetch)


def query_censys_ip(ip: str, api_id: str, api_secret: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"censys:ip:{ip}"

    def fetch():
        url = f"https://search.censys.io/api/v2/hosts/{ip}"
        response = session.get(url, auth=(api_id, api_secret), timeout=REQUEST_TIMEOUT)
        if response.status_code in (401, 403):
            _mark_provider_unavailable("censys", "invalid or unauthorized API credentials")
            return None
        if response.status_code == 404:
            return None
        response.raise_for_status()
        result = response.json().get("result", {})

        services = []
        ports = []
        vulns = []

        for svc in result.get("services", []) or []:
            if svc.get("service_name"):
                services.append(svc["service_name"])
            if svc.get("port") is not None:
                ports.append(svc["port"])
            for v in svc.get("vulnerabilities", []) or []:
                if isinstance(v, dict) and v.get("cve"):
                    vulns.append(v["cve"])
                elif isinstance(v, str):
                    vulns.append(v)

        return normalize_exposure_hit(
            provider="censys",
            target_type="ip",
            target=ip,
            open_ports=safe_int_list(ports),
            hostnames=((result.get("dns") or {}).get("names") or []),
            services=dedupe_list(services),
            organization=((result.get("autonomous_system") or {}).get("description")
                          or (result.get("autonomous_system") or {}).get("name")),
            asn=(result.get("autonomous_system") or {}).get("asn"),
            country=(result.get("location") or {}).get("country"),
            vulnerabilities=dedupe_list(vulns),
            last_seen=result.get("last_updated_at"),
            confidence=0.88,
            raw=result,
        )

    return cached_fetch(cache_key, fetch)


def query_virustotal_ip(ip: str, api_key: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"virustotal:ip:{ip}"

    def fetch():
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = session.get(url, headers={"x-apikey": api_key}, timeout=REQUEST_TIMEOUT)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json().get("data", {})
        attrs = data.get("attributes", {})

        hostnames = []
        for item in attrs.get("resolutions", []) or []:
            if isinstance(item, dict):
                if item.get("hostname"):
                    hostnames.append(item["hostname"])
                elif item.get("host_name"):
                    hostnames.append(item["host_name"])

        return normalize_exposure_hit(
            provider="virustotal",
            target_type="ip",
            target=ip,
            open_ports=[],
            hostnames=dedupe_list(hostnames),
            services=[],
            organization=attrs.get("as_owner"),
            asn=attrs.get("asn"),
            country=attrs.get("country"),
            vulnerabilities=[],
            last_seen=attrs.get("last_modification_date"),
            tags=[],
            confidence=0.75,
            raw=data,
        )

    return cached_fetch(cache_key, fetch)


def query_bgpview_ip(ip: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"bgpview:ip:{ip}"

    def fetch():
        url = f"https://api.bgpview.io/ip/{ip}"
        response = session.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data", {})

        prefixes = []
        for p in data.get("prefixes", []) or []:
            if isinstance(p, dict) and p.get("prefix"):
                prefixes.append(p["prefix"])

        return normalize_exposure_hit(
            provider="bgpview",
            target_type="ip",
            target=ip,
            open_ports=[],
            hostnames=[],
            services=[],
            organization=(data.get("rir_allocation") or {}).get("name"),
            asn=(data.get("asn") or {}).get("asn"),
            country=(data.get("maxmind") or {}).get("country_code"),
            vulnerabilities=[],
            last_seen=None,
            tags=[],
            confidence=0.70,
            raw=data,
            extra={"prefixes": dedupe_list(prefixes)},
        )

    return cached_fetch(cache_key, fetch)


def query_ipinfo_ip(ip: str, api_key: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"ipinfo:ip:{ip}"

    def fetch():
        url = f"https://api.ipinfo.io/lite/{quote(ip)}?token={quote(api_key)}"
        response = session.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code in (401, 403, 404):
            return None
        response.raise_for_status()
        data = response.json()

        return normalize_exposure_hit(
            provider="ipinfo",
            target_type="ip",
            target=ip,
            open_ports=[],
            hostnames=[],
            services=[],
            organization=data.get("as_name"),
            asn=data.get("asn"),
            country=data.get("country_code") or data.get("country"),
            vulnerabilities=[],
            last_seen=None,
            tags=dedupe_list([
                data.get("continent"),
                data.get("as_domain"),
            ]),
            confidence=0.7,
            raw=data,
            extra={
                "as_domain": data.get("as_domain"),
                "continent": data.get("continent_code") or data.get("continent"),
            },
        )

    return cached_fetch(cache_key, fetch)


# ---------------------------------------------------------------------------
# Domain providers
# ---------------------------------------------------------------------------

def query_virustotal_domain(domain: str, api_key: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"virustotal:domain:{domain}"

    def fetch():
        url = f"https://www.virustotal.com/api/v3/domains/{quote(domain)}"
        response = session.get(url, headers={"x-apikey": api_key}, timeout=REQUEST_TIMEOUT)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json().get("data", {})
        attrs = data.get("attributes", {})

        return normalize_exposure_hit(
            provider="virustotal",
            target_type="domain",
            target=domain,
            open_ports=[],
            hostnames=[domain],
            services=[],
            organization=None,
            asn=None,
            country=None,
            vulnerabilities=[],
            last_seen=attrs.get("last_modification_date"),
            confidence=0.72,
            raw=data,
        )

    return cached_fetch(cache_key, fetch)


def query_securitytrails_domain(domain: str, api_key: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"securitytrails:domain:{domain}"

    def fetch():
        # Using the associated-domains endpoint as a practical defensive-enrichment lookup
        url = f"https://api.securitytrails.com/v1/domain/{quote(domain)}/associated"
        response = session.get(url, headers={"APIKEY": api_key}, timeout=REQUEST_TIMEOUT)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()

        hostnames = [domain]
        for item in data.get("records", []) or []:
            if isinstance(item, dict) and item.get("hostname"):
                hostnames.append(item["hostname"])
            elif isinstance(item, str):
                hostnames.append(item)

        return normalize_exposure_hit(
            provider="securitytrails",
            target_type="domain",
            target=domain,
            open_ports=[],
            hostnames=dedupe_list(hostnames),
            services=[],
            organization=None,
            asn=None,
            country=None,
            vulnerabilities=[],
            last_seen=data.get("meta", {}).get("last_updated"),
            confidence=0.70,
            raw=data,
        )

    return cached_fetch(cache_key, fetch)


def query_hostio_domain(domain: str, api_key: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"hostio:domain:{domain}"

    def fetch():
        url = f"https://host.io/api/full/{quote(domain)}"
        response = session.get(
            url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()

        hostnames = [domain]
        dns = data.get("dns", {})
        ips = []
        for val in dns.get("a", []) or []:
            if val:
                ips.append(val)

        asn_name = None
        asn_number = None
        country = None
        ipinfo = data.get("ipinfo", {}) or {}
        for _, details in ipinfo.items():
            if not isinstance(details, dict):
                continue
            country = country or details.get("country")
            asn = details.get("asn") or {}
            asn_name = asn_name or asn.get("name")
            asn_number = asn_number or asn.get("asn")

        services = []
        web = data.get("web", {}) or {}
        if web.get("server"):
            services.append(web["server"])

        return normalize_exposure_hit(
            provider="hostio",
            target_type="domain",
            target=domain,
            open_ports=[],
            hostnames=hostnames,
            services=services,
            organization=asn_name,
            asn=asn_number,
            country=country,
            vulnerabilities=[],
            last_seen=web.get("date"),
            tags=[],
            confidence=0.78,
            raw=data,
            extra={"resolved_ips": dedupe_list(ips)},
        )

    return cached_fetch(cache_key, fetch)


def query_builtwith_domain(domain: str, api_key: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"builtwith:domain:{domain}"

    def fetch():
        url = f"https://api.builtwith.com/v22/api.json?KEY={quote(api_key)}&LOOKUP={quote(domain)}"
        response = session.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code in (401, 403, 404):
            return None
        response.raise_for_status()
        data = response.json()

        results = data.get("Results", []) or []
        if not results:
            return None

        result_entry = results[0] or {}
        result = result_entry.get("Result", {}) or {}
        meta = result_entry.get("Meta", {}) or {}

        hostnames = set()
        technologies = []
        services = []
        tags = []

        for path in result.get("Paths", []) or []:
            if not isinstance(path, dict):
                continue

            root_domain = path.get("Domain") or domain
            subdomain = (path.get("SubDomain") or "").strip(".")
            if subdomain:
                hostnames.add(f"{subdomain}.{root_domain}")
            else:
                hostnames.add(str(root_domain))

            for tech in path.get("Technologies", []) or []:
                if not isinstance(tech, dict):
                    continue
                name = tech.get("Name")
                if name:
                    technologies.append(str(name))
                    services.append(str(name))
                parent = tech.get("Parent")
                if parent:
                    services.append(str(parent))
                tag = tech.get("Tag")
                if tag:
                    tags.append(str(tag))
                for category in tech.get("Categories", []) or []:
                    if category:
                        tags.append(str(category))

        return normalize_exposure_hit(
            provider="builtwith",
            target_type="domain",
            target=domain,
            open_ports=[],
            hostnames=sorted(hostnames) or [domain],
            services=dedupe_list(services),
            organization=meta.get("CompanyName"),
            asn=None,
            country=meta.get("Country"),
            vulnerabilities=[],
            last_seen=result_entry.get("LastIndexed") or result.get("LastIndexed"),
            tags=dedupe_list(tags),
            confidence=0.76,
            raw=data,
            extra={
                "technologies": dedupe_list(technologies),
                "technology_count": len(dedupe_list(technologies)),
                "builtwith_vertical": meta.get("Vertical"),
                "builtwith_socials": dedupe_list(meta.get("Social", []) or []),
            },
        )

    return cached_fetch(cache_key, fetch)


def query_domainsdb_domain(
    domain: str,
    api_key: Optional[str],
    session: requests.Session,
) -> Optional[Dict[str, Any]]:
    cache_key = f"domainsdb:domain:{domain}"

    def fetch():
        # Best-effort adapter. If the service requires auth on your plan, set DOMAINSDB_API_KEY.
        url = f"https://api.domainsdb.info/v1/domains/search?domain={quote(domain)}"
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        response = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code in (401, 403, 404):
            return None
        response.raise_for_status()
        data = response.json()

        matches = data.get("domains", []) or []
        hostnames = []
        countries = []
        for item in matches:
            if not isinstance(item, dict):
                continue
            if item.get("domain"):
                hostnames.append(item["domain"])
            if item.get("country"):
                countries.append(item["country"])

        return normalize_exposure_hit(
            provider="domainsdb",
            target_type="domain",
            target=domain,
            open_ports=[],
            hostnames=dedupe_list(hostnames) or [domain],
            services=[],
            organization=None,
            asn=None,
            country=",".join(dedupe_list(countries)) if countries else None,
            vulnerabilities=[],
            last_seen=None,
            confidence=0.60,
            raw=data,
        )

    return cached_fetch(cache_key, fetch)


def query_cloudflare_trace(domain: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"cloudflare_trace:domain:{domain}"

    def fetch():
        # Best-effort only: this reflects the current request path through Cloudflare for the hostname.
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}/cdn-cgi/trace"
            try:
                response = session.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    headers={"Accept": "text/plain"},
                    allow_redirects=True,
                )
                if response.status_code != 200:
                    continue

                parsed = parse_key_value_lines(response.text)
                if not parsed:
                    continue

                tags = []
                if parsed.get("warp") == "on":
                    tags.append("warp")
                if parsed.get("http"):
                    tags.append(f"http/{parsed['http']}")
                if parsed.get("tls"):
                    tags.append(f"tls/{parsed['tls']}")

                return normalize_exposure_hit(
                    provider="cloudflare_trace",
                    target_type="domain",
                    target=domain,
                    open_ports=[],
                    hostnames=[domain],
                    services=["cloudflare_edge"],
                    organization="Cloudflare",
                    asn=None,
                    country=parsed.get("loc"),
                    vulnerabilities=[],
                    last_seen=parsed.get("ts"),
                    tags=tags,
                    confidence=0.55,
                    raw=parsed,
                )
            except requests.exceptions.RequestException:
                continue

        return None

    return cached_fetch(cache_key, fetch)


# ---------------------------------------------------------------------------
# Netlas providers
# ---------------------------------------------------------------------------

def query_netlas_ip(ip: str, api_key: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"netlas:ip:{ip}"

    def fetch():
        url = "https://app.netlas.io/api/responses/"
        params = {"q": f"ip:{ip}", "source_type": "include", "start": 0, "fields": "*"}
        response = session.get(
            url,
            params=params,
            headers={"X-API-Key": api_key},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code in (401, 403, 404):
            return None
        response.raise_for_status()
        data = response.json()

        items = data.get("items", []) or []
        if not items:
            return None

        ports = []
        services = []
        hostnames = []
        vulns = []
        tags = []

        for item in items:
            d = item.get("data", {}) or {}
            port = d.get("port")
            if port is not None:
                ports.append(port)
            proto = d.get("protocol") or d.get("app", {}).get("protocol")
            if proto:
                services.append(str(proto))
            for h in d.get("rdns_names", []) or []:
                if h:
                    hostnames.append(str(h))
            for cpe in d.get("cpe", []) or []:
                if cpe:
                    tags.append(str(cpe))
            for v in d.get("vulns", {}).get("cve", []) if isinstance(d.get("vulns"), dict) else []:
                if v:
                    vulns.append(str(v))

        first = (items[0].get("data") or {}) if items else {}
        geo = first.get("geo", {}) or {}
        asn_info = first.get("as", {}) or {}

        return normalize_exposure_hit(
            provider="netlas",
            target_type="ip",
            target=ip,
            open_ports=safe_int_list(ports),
            hostnames=dedupe_list(hostnames),
            services=dedupe_list(services),
            organization=asn_info.get("name"),
            asn=str(asn_info["number"]) if asn_info.get("number") is not None else None,
            country=geo.get("country") or geo.get("country_iso_code"),
            vulnerabilities=dedupe_list(vulns),
            last_seen=first.get("timestamp"),
            tags=dedupe_list(tags),
            confidence=0.87,
            raw=data,
        )

    return cached_fetch(cache_key, fetch)


def query_netlas_domain(domain: str, api_key: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"netlas:domain:{domain}"

    def fetch():
        url = "https://app.netlas.io/api/responses/"
        params = {"q": f"host:{domain}", "source_type": "include", "start": 0, "fields": "*"}
        response = session.get(
            url,
            params=params,
            headers={"X-API-Key": api_key},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code in (401, 403, 404):
            return None
        response.raise_for_status()
        data = response.json()

        items = data.get("items", []) or []
        if not items:
            return None

        ports = []
        services = []
        ips = []
        tags = []
        vulns = []

        for item in items:
            d = item.get("data", {}) or {}
            port = d.get("port")
            if port is not None:
                ports.append(port)
            proto = d.get("protocol") or d.get("app", {}).get("protocol")
            if proto:
                services.append(str(proto))
            ip_val = d.get("ip")
            if ip_val:
                ips.append(str(ip_val))
            for cpe in d.get("cpe", []) or []:
                if cpe:
                    tags.append(str(cpe))
            for v in d.get("vulns", {}).get("cve", []) if isinstance(d.get("vulns"), dict) else []:
                if v:
                    vulns.append(str(v))

        return normalize_exposure_hit(
            provider="netlas",
            target_type="domain",
            target=domain,
            open_ports=safe_int_list(ports),
            hostnames=[domain],
            services=dedupe_list(services),
            organization=None,
            asn=None,
            country=None,
            vulnerabilities=dedupe_list(vulns),
            last_seen=None,
            tags=dedupe_list(tags),
            confidence=0.85,
            raw=data,
            extra={"resolved_ips": dedupe_list(ips)},
        )

    return cached_fetch(cache_key, fetch)


# ---------------------------------------------------------------------------
# IntelX providers
# ---------------------------------------------------------------------------

def query_intelx_domain(domain: str, api_key: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"intelx:domain:{domain}"

    def fetch():
        search_url = "https://2.intelx.io/intelligent/search"
        headers = {"X-Key": api_key, "Content-Type": "application/json"}

        search_resp = session.post(
            search_url,
            headers=headers,
            json={"term": domain, "maxResults": 10, "media": 0, "sort": 4, "terminate": []},
            timeout=REQUEST_TIMEOUT,
        )
        if search_resp.status_code in (401, 403, 404):
            return None
        search_resp.raise_for_status()
        search_data = search_resp.json()

        search_id = search_data.get("id")
        if not search_id:
            return None

        results_resp = session.get(
            "https://2.intelx.io/intelligent/search/result",
            headers=headers,
            params={"id": search_id, "limit": 10},
            timeout=REQUEST_TIMEOUT,
        )
        if results_resp.status_code in (401, 403, 404):
            return None
        results_resp.raise_for_status()
        results = results_resp.json()

        records = results.get("records", []) or []
        if not records:
            return None

        buckets = []
        media_types = []
        for rec in records:
            bucket = rec.get("bucket")
            if bucket:
                buckets.append(str(bucket))
            media = rec.get("media")
            if media is not None:
                media_types.append(str(media))

        return normalize_exposure_hit(
            provider="intelx",
            target_type="domain",
            target=domain,
            open_ports=[],
            hostnames=[domain],
            services=[],
            organization=None,
            asn=None,
            country=None,
            vulnerabilities=[],
            last_seen=records[0].get("date") if records else None,
            tags=dedupe_list(buckets),
            confidence=0.72,
            raw=results,
            extra={
                "intelx_record_count": len(records),
                "intelx_buckets": dedupe_list(buckets),
            },
        )

    return cached_fetch(cache_key, fetch)


# ---------------------------------------------------------------------------
# FullHunt providers
# ---------------------------------------------------------------------------

def query_fullhunt_ip(ip: str, api_key: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"fullhunt:ip:{ip}"

    def fetch():
        url = f"https://fullhunt.io/api/v1/host/{ip}"
        response = session.get(
            url,
            headers={"X-API-KEY": api_key},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code in (401, 403, 404):
            return None
        response.raise_for_status()
        data = response.json()

        hosts = data.get("hosts", []) or []
        if not hosts:
            return None

        ports = []
        services = []
        hostnames = []
        tags = []

        for host in hosts:
            for port in host.get("ports", []) or []:
                ports.append(port)
            for svc in host.get("services", []) or []:
                if svc:
                    services.append(str(svc))
            fqdn = host.get("fqdn") or host.get("hostname")
            if fqdn:
                hostnames.append(str(fqdn))
            for tag in host.get("tags", []) or []:
                if tag:
                    tags.append(str(tag))

        first = hosts[0] if hosts else {}
        return normalize_exposure_hit(
            provider="fullhunt",
            target_type="ip",
            target=ip,
            open_ports=safe_int_list(ports),
            hostnames=dedupe_list(hostnames),
            services=dedupe_list(services),
            organization=first.get("organization") or first.get("isp"),
            asn=str(first["as_number"]) if first.get("as_number") is not None else None,
            country=first.get("country_code") or first.get("country"),
            vulnerabilities=[],
            last_seen=first.get("last_seen"),
            tags=dedupe_list(tags),
            confidence=0.85,
            raw=data,
        )

    return cached_fetch(cache_key, fetch)


def query_fullhunt_domain(domain: str, api_key: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"fullhunt:domain:{domain}"

    def fetch():
        url = f"https://fullhunt.io/api/v1/domain/{quote(domain)}/subdomains"
        response = session.get(
            url,
            headers={"X-API-KEY": api_key},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code in (401, 403, 404):
            return None
        response.raise_for_status()
        data = response.json()

        hosts = data.get("hosts", []) or []
        if not hosts:
            return None

        subdomains = []
        ips = []
        ports = []
        services = []
        tags = []

        for host in hosts:
            fqdn = host.get("fqdn") or host.get("hostname")
            if fqdn:
                subdomains.append(str(fqdn))
            for ip_val in host.get("ip_addresses", []) or []:
                if ip_val:
                    ips.append(str(ip_val))
            for port in host.get("ports", []) or []:
                ports.append(port)
            for svc in host.get("services", []) or []:
                if svc:
                    services.append(str(svc))
            for tag in host.get("tags", []) or []:
                if tag:
                    tags.append(str(tag))

        return normalize_exposure_hit(
            provider="fullhunt",
            target_type="domain",
            target=domain,
            open_ports=safe_int_list(ports),
            hostnames=dedupe_list(subdomains) or [domain],
            services=dedupe_list(services),
            organization=None,
            asn=None,
            country=None,
            vulnerabilities=[],
            last_seen=None,
            tags=dedupe_list(tags),
            confidence=0.85,
            raw=data,
            extra={
                "subdomain_count": len(dedupe_list(subdomains)),
                "resolved_ips": dedupe_list(ips),
            },
        )

    return cached_fetch(cache_key, fetch)


# ---------------------------------------------------------------------------
# Vulnerability providers
# ---------------------------------------------------------------------------

def query_nvd_cve(cve_id: str, api_key: Optional[str], session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"nvd:cve:{cve_id}"

    def fetch():
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={quote(cve_id)}"
        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        response = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()

        vulns = data.get("vulnerabilities", []) or []
        if not vulns:
            return None

        cve = vulns[0].get("cve", {})
        descriptions = cve.get("descriptions", []) or []
        description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)

        metrics = cve.get("metrics", {}) or {}
        cvss = extract_nvd_cvss(metrics)

        return normalize_vuln_hit(
            provider="nvd",
            cve_id=cve_id,
            summary=description,
            severity=cvss.get("severity"),
            score=cvss.get("score"),
            published=cve.get("published"),
            last_modified=cve.get("lastModified"),
            kev=False,
            raw=cve,
        )

    return cached_fetch(cache_key, fetch)


def query_opencve_cve(
    cve_id: str,
    token: Optional[str],
    username: Optional[str],
    password: Optional[str],
    session: requests.Session,
) -> Optional[Dict[str, Any]]:
    cache_key = f"opencve:cve:{cve_id}"

    def fetch():
        url = f"https://app.opencve.io/api/cve/{quote(cve_id)}"
        headers = {}
        auth = None

        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif username and password:
            auth = (username, password)
        else:
            return None

        response = session.get(url, headers=headers, auth=auth, timeout=REQUEST_TIMEOUT)
        if response.status_code in (401, 403, 404):
            return None
        response.raise_for_status()
        data = response.json()

        severity = None
        score = None
        cvss = data.get("cvss31") or data.get("cvss3") or {}
        if isinstance(cvss, dict):
            severity = cvss.get("severity")
            score = cvss.get("score")

        return normalize_vuln_hit(
            provider="opencve",
            cve_id=data.get("cve_id", cve_id),
            summary=data.get("description"),
            severity=severity,
            score=score,
            published=data.get("created_at"),
            last_modified=data.get("updated_at"),
            kev=False,
            raw=data,
        )

    return cached_fetch(cache_key, fetch)


def query_kevin_cve(cve_id: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"kevin:cve:{cve_id}"

    def fetch():
        details_url = f"https://kevin.gtfkd.com/vuln/{quote(cve_id)}"
        details_response = session.get(details_url, timeout=REQUEST_TIMEOUT)
        if details_response.status_code == 404:
            return None
        details_response.raise_for_status()
        details = details_response.json()

        kev_url = f"https://kevin.gtfkd.com/kev/exists?cve={quote(cve_id)}"
        kev_response = session.get(kev_url, timeout=REQUEST_TIMEOUT)

        kev = False
        kev_raw = None
        if kev_response.status_code == 200:
            try:
                kev_raw = kev_response.json()
                if isinstance(kev_raw, dict):
                    kev = bool(
                        kev_raw.get("exists")
                        or kev_raw.get("kev")
                        or kev_raw.get("known_exploited")
                        or kev_raw.get("present")
                    )
            except Exception:
                kev_raw = None

        summary = None
        score = None
        severity = None

        if isinstance(details, dict):
            summary = (
                details.get("summary")
                or details.get("description")
                or ((details.get("cve") or {}).get("descriptions") or [None])[0]
            )
            score = details.get("cvss") or details.get("cvss_score")
            severity = details.get("severity")

        return normalize_vuln_hit(
            provider="kevin",
            cve_id=cve_id,
            summary=summary,
            severity=severity,
            score=score,
            published=details.get("published") if isinstance(details, dict) else None,
            last_modified=details.get("updated") if isinstance(details, dict) else None,
            kev=kev,
            raw={"vuln": details, "kev_exists": kev_raw},
        )

    return cached_fetch(cache_key, fetch)


def query_vulners_cve(cve_id: str, api_key: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"vulners:cve:{cve_id}"

    def fetch():
        url = "https://vulners.com/api/v3/search/id"
        response = session.post(
            url,
            headers={
                "X-Api-Key": api_key,
                "Content-Type": "application/json",
            },
            json={
                "id": [cve_id],
                "fields": ["*"],
                "references": True,
            },
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code in (401, 403, 404):
            return None
        response.raise_for_status()
        data = response.json()

        documents = ((data.get("data") or {}).get("documents") or {})
        doc = documents.get(cve_id)
        if not doc:
            # some deployments return keys in lower case or a list
            if isinstance(documents, list) and documents:
                doc = documents[0]
            else:
                return None

        return normalize_vuln_hit(
            provider="vulners",
            cve_id=cve_id,
            summary=doc.get("description") or doc.get("title"),
            severity=doc.get("cvss", {}).get("severity")
            if isinstance(doc.get("cvss"), dict)
            else None,
            score=doc.get("cvss", {}).get("score")
            if isinstance(doc.get("cvss"), dict)
            else doc.get("cvss", {}).get("score")
            if isinstance(doc.get("cvss"), dict)
            else None,
            published=doc.get("published"),
            last_modified=doc.get("modified"),
            kev=bool(doc.get("cisaKnownExploited") or doc.get("kev")),
            raw=doc,
        )

    return cached_fetch(cache_key, fetch)


def _extract_vuldb_cvss(vulnerability: Dict[str, Any]) -> tuple:
    for key in ("cvss3", "cvss4", "cvss2"):
        section = vulnerability.get(key, {}) or {}
        meta = section.get("meta", {}) or {}
        if meta.get("basescore") is not None:
            try:
                return float(meta["basescore"]), meta.get("baseseverity")
            except (ValueError, TypeError):
                pass
        vuldb = section.get("vuldb", {}) or {}
        if vuldb.get("basescore") is not None:
            try:
                return float(vuldb["basescore"]), vuldb.get("baseseverity")
            except (ValueError, TypeError):
                pass
    return None, None


def query_vuldb_cve(cve_id: str, api_key: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    cache_key = f"vuldb:cve:{cve_id}"

    def fetch():
        url = "https://vuldb.com/api"
        response = session.post(
            url,
            headers={"X-VulDB-ApiKey": api_key},
            data={"search": cve_id, "details": "1"},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code in (204, 401, 402, 403, 404, 405, 429):
            return None
        response.raise_for_status()
        data = response.json()

        resp_header = data.get("response", {})
        if str(resp_header.get("status")) == "204":
            return None

        results = data.get("result", []) or []
        if not results:
            return None

        entry = results[0]
        source = entry.get("source", {}) or {}
        advisory = entry.get("advisory", {}) or {}
        vulnerability = entry.get("vulnerability", {}) or {}
        exploit = entry.get("exploit", {}) or {}
        entry_meta = entry.get("entry", {}) or {}
        timestamp = entry_meta.get("timestamp", {}) or {}

        score, severity = _extract_vuldb_cvss(vulnerability)

        return normalize_vuln_hit(
            provider="vuldb",
            cve_id=(source.get("cve", {}) or {}).get("id") or cve_id,
            summary=(source.get("cve", {}) or {}).get("summary")
                    or entry_meta.get("title")
                    or advisory.get("title"),
            severity=severity,
            score=score,
            published=advisory.get("date") or timestamp.get("create"),
            last_modified=timestamp.get("change"),
            kev=bool(exploit.get("kev")),
            raw=entry,
        )

    return cached_fetch(cache_key, fetch)


# ---------------------------------------------------------------------------
# Normalization / merging
# ---------------------------------------------------------------------------

def normalize_exposure_hit(
    provider: str,
    target_type: str,
    target: str,
    open_ports: Optional[List[Any]] = None,
    hostnames: Optional[List[Any]] = None,
    services: Optional[List[Any]] = None,
    organization: Optional[Any] = None,
    asn: Optional[Any] = None,
    country: Optional[Any] = None,
    vulnerabilities: Optional[List[Any]] = None,
    last_seen: Optional[Any] = None,
    tags: Optional[List[Any]] = None,
    confidence: float = 0.5,
    raw: Optional[Any] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    record = {
        "provider": provider,
        "target_type": target_type,
        "target": target,
        "open_ports": safe_int_list(open_ports or []),
        "hostnames": dedupe_list([str(x) for x in (hostnames or []) if x]),
        "services": dedupe_list([str(x) for x in (services or []) if x]),
        "organization": str(organization) if organization is not None else None,
        "asn": str(asn) if asn is not None else None,
        "country": str(country) if country is not None else None,
        "vulnerabilities": dedupe_list([str(x) for x in (vulnerabilities or []) if x]),
        "last_seen": last_seen,
        "tags": dedupe_list([str(x) for x in (tags or []) if x]),
        "confidence": float(confidence),
        "raw": raw,
    }
    if extra:
        record.update(extra)
    return record


def normalize_vuln_hit(
    provider: str,
    cve_id: str,
    summary: Optional[Any] = None,
    severity: Optional[Any] = None,
    score: Optional[Any] = None,
    published: Optional[Any] = None,
    last_modified: Optional[Any] = None,
    kev: bool = False,
    raw: Optional[Any] = None,
) -> Dict[str, Any]:
    try:
        score_val = float(score) if score is not None else None
    except Exception:
        score_val = None

    return {
        "provider": provider,
        "cve_id": cve_id,
        "summary": str(summary)[:500] if summary else None,
        "severity": str(severity) if severity is not None else None,
        "score": score_val,
        "published": published,
        "last_modified": last_modified,
        "kev": bool(kev),
        "raw": raw,
    }


def merge_provider_hits(provider_hits: List[Dict[str, Any]]) -> Dict[str, Any]:
    open_ports: Set[int] = set()
    hostnames: Set[str] = set()
    services: Set[str] = set()
    vulnerabilities: Set[str] = set()
    organizations: Set[str] = set()
    countries: Set[str] = set()
    asns: Set[str] = set()
    tags: Set[str] = set()
    prefixes: Set[str] = set()

    for hit in provider_hits:
        open_ports.update(hit.get("open_ports", []))
        hostnames.update(hit.get("hostnames", []))
        services.update(hit.get("services", []))
        vulnerabilities.update(hit.get("vulnerabilities", []))
        tags.update(hit.get("tags", []))

        if hit.get("organization"):
            organizations.add(hit["organization"])
        if hit.get("country"):
            countries.add(hit["country"])
        if hit.get("asn"):
            asns.add(hit["asn"])
        for pfx in hit.get("prefixes", []) or []:
            prefixes.add(str(pfx))

    return {
        "providers": provider_hits,
        "summary": {
            "provider_count": len(provider_hits),
            "provider_names": [h["provider"] for h in provider_hits],
            "open_ports": sorted(open_ports),
            "hostnames": sorted(hostnames),
            "services": sorted(services),
            "vulnerabilities": sorted(vulnerabilities),
            "organizations": sorted(organizations),
            "countries": sorted(countries),
            "asns": sorted(asns),
            "tags": sorted(tags),
            "prefixes": sorted(prefixes),
        },
    }


def merge_vulnerability_hits(vuln_hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}

    for hit in vuln_hits:
        cve_id = hit["cve_id"]
        entry = grouped.setdefault(
            cve_id,
            {
                "cve_id": cve_id,
                "providers": [],
                "summaries": [],
                "severities": [],
                "scores": [],
                "published": [],
                "last_modified": [],
                "kev": False,
            },
        )

        entry["providers"].append(hit["provider"])
        if hit.get("summary"):
            entry["summaries"].append(hit["summary"])
        if hit.get("severity"):
            entry["severities"].append(hit["severity"])
        if hit.get("score") is not None:
            entry["scores"].append(hit["score"])
        if hit.get("published"):
            entry["published"].append(hit["published"])
        if hit.get("last_modified"):
            entry["last_modified"].append(hit["last_modified"])
        entry["kev"] = entry["kev"] or bool(hit.get("kev"))

    merged = []
    for cve_id, entry in grouped.items():
        merged.append(
            {
                "cve_id": cve_id,
                "providers": dedupe_list(entry["providers"]),
                "summary": entry["summaries"][0] if entry["summaries"] else None,
                "severity": most_common(entry["severities"]),
                "score": max(entry["scores"]) if entry["scores"] else None,
                "published": min(entry["published"]) if entry["published"] else None,
                "last_modified": max(entry["last_modified"]) if entry["last_modified"] else None,
                "kev": entry["kev"],
            }
        )

    return sorted(merged, key=lambda x: (x["kev"], x["score"] or 0), reverse=True)


def score_exposure(exposure: Dict[str, Any]) -> int:
    summary = exposure.get("summary", {})
    score = 0

    provider_count = len(summary.get("provider_names", []))
    open_ports = len(summary.get("open_ports", []))
    vulns = len(summary.get("vulnerabilities", []))
    tags = len(summary.get("tags", []))

    score += min(provider_count * 12, 30)
    score += min(open_ports * 4, 30)
    score += min(vulns * 10, 30)
    score += min(tags * 2, 10)

    if any(p in [22, 23, 3389, 445, 5900, 8080, 8443] for p in summary.get("open_ports", [])):
        score += 5

    return min(score, 100)


# ---------------------------------------------------------------------------
# Asset helpers
# ---------------------------------------------------------------------------

def get_public_ip_for_osint(asset: Dict[str, Any]) -> Optional[str]:
    for candidate in [asset.get("public_ip"), asset.get("ip")]:
        if candidate and is_public_ip(str(candidate)):
            return str(candidate)
    return None


def get_public_domains_for_osint(asset: Dict[str, Any]) -> List[str]:
    candidates = {
        asset.get("hostname"),
        asset.get("fqdn"),
        asset.get("endpoint"),
    }

    domains = []
    for candidate in candidates:
        if not candidate:
            continue
        value = str(candidate).strip().lower()
        if is_likely_public_domain(value):
            domains.append(value)

    return dedupe_list(domains)


def extract_cve_ids(asset: Dict[str, Any]) -> List[str]:
    cve_ids = set()

    for vuln in asset.get("vulnerabilities", []) or []:
        if isinstance(vuln, dict):
            candidate = vuln.get("cve_id") or vuln.get("id")
            if candidate and str(candidate).upper().startswith("CVE-"):
                cve_ids.add(str(candidate).upper())
        elif isinstance(vuln, str) and vuln.upper().startswith("CVE-"):
            cve_ids.add(vuln.upper())

    # also pull from OSINT exposure if prior providers already returned CVEs
    exposure = asset.get("osint_exposure", {}) or {}
    for provider in exposure.get("providers", []) or []:
        for candidate in provider.get("vulnerabilities", []) or []:
            value = str(candidate).upper()
            if value.startswith("CVE-"):
                cve_ids.add(value)

    return sorted(cve_ids)


def is_likely_web_asset(asset: Dict[str, Any]) -> bool:
    services = [str(s).lower() for s in asset.get("services", []) or []]
    ports = [str(p.get("port")) for p in asset.get("ports", []) or []]
    return any(s in {"http", "https", "apache", "nginx", "iis"} for s in services) or any(
        p in {"80", "443", "8080", "8443"} for p in ports
    )


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return bool(ip.is_global)
    except ValueError:
        return False


def is_likely_public_domain(value: str) -> bool:
    if not value or " " in value:
        return False

    if value.endswith((".local", ".lan", ".internal", ".home", ".corp")):
        return False

    if "." not in value:
        return False

    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        return True


def parse_key_value_lines(text: str) -> Dict[str, str]:
    parsed = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def dedupe_list(values: Iterable[Any]) -> List[Any]:
    seen = set()
    result = []
    for value in values:
        # Use json.dumps only for unhashable types; use value directly for scalars
        marker = json.dumps(value, sort_keys=True, default=str) if isinstance(value, (dict, list)) else value
        if marker not in seen:
            seen.add(marker)
            result.append(value)
    return result


def safe_int_list(values: Iterable[Any]) -> List[int]:
    result = []
    for value in values:
        try:
            result.append(int(value))
        except Exception:
            continue
    return dedupe_list(result)


def most_common(values: List[Any]) -> Optional[Any]:
    if not values:
        return None
    counts: Dict[Any, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[0][0]


def extract_nvd_cvss(metrics: Dict[str, Any]) -> Dict[str, Any]:
    # Prefer newer metrics first
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = entries[0]
        cvss_data = entry.get("cvssData", {})
        return {
            "score": cvss_data.get("baseScore"),
            "severity": cvss_data.get("baseSeverity") or entry.get("baseSeverity"),
        }
    return {"score": None, "severity": None}


def cache_path(cache_key: str) -> Path:
    digest = hashlib.sha256(cache_key.encode("utf-8")).hexdigest()
    return CACHE_DIR / f"{digest}.json"


def cached_fetch(cache_key: str, fetch_fn):
    provider = cache_key.split(":", 1)[0]
    if provider in _UNAVAILABLE_PROVIDERS:
        return None

    path = cache_path(cache_key)

    if path.exists():
        age = time.time() - path.stat().st_mtime
        if age <= CACHE_TTL_SECONDS:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass

    try:
        result = fetch_fn()
        path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        return result
    except requests.exceptions.RequestException as e:
        print(f"  [!] OSINT request failed for {cache_key}: {_safe_request_error(e)}")
        _mark_provider_unavailable(provider)
        return None
    except Exception as e:
        print(f"  [!] OSINT processing failed for {cache_key}: {_redact_secrets(str(e))}")
        return None


_SECRET_QUERY_RE = re.compile(
    r"(?i)([?&](?:key|api[_-]?key|apikey|token|access[_-]?token|secret|password)=)([^&\s)]+)"
)


def _redact_secrets(message: str) -> str:
    return _SECRET_QUERY_RE.sub(r"\1<redacted>", message)


def _safe_request_error(error: requests.exceptions.RequestException) -> str:
    response = getattr(error, "response", None)
    if response is not None and getattr(response, "status_code", None):
        return f"{response.status_code} {getattr(response, 'reason', '').strip() or type(error).__name__}"

    message = _redact_secrets(str(error))
    if len(message) > 220:
        message = f"{message[:217]}..."
    return message or type(error).__name__


def _skip_providers() -> Set[str]:
    return {
        item.strip().lower()
        for item in os.environ.get("INVENTA_OSINT_SKIP_PROVIDERS", "").split(",")
        if item.strip()
    }


def _mark_provider_unavailable(provider: str, reason: Optional[str] = None) -> None:
    if provider in _UNAVAILABLE_PROVIDERS:
        return
    _UNAVAILABLE_PROVIDERS.add(provider)
    if reason:
        print(f"  [!] OSINT provider disabled for this run: {provider} ({reason})")
