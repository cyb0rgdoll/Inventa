"""
Hunter.how OSINT Module for Inventa.

Queries the Hunter.how search engine API to surface IP addresses, open ports,
and domains/hostnames associated with a target domain or IP.

Uses the same query syntax as the hunter.how website. Returns infrastructure
exposure data useful for attack surface mapping.

Environment variable:
  HUNTER_API_KEY   — required; obtain from https://hunter.how

Writes per-asset:
  asset["hunter_findings"]  — dict with results, ports, domains, and meta
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


import requests


REQUEST_TIMEOUT = int(os.environ.get("INVENTA_OSINT_TIMEOUT", "15"))
CACHE_TTL = int(os.environ.get("INVENTA_OSINT_CACHE_TTL", "43200"))
CACHE_DIR = Path(os.environ.get(
    "INVENTA_OSINT_CACHE_DIR",
    str(Path.home() / ".inventa" / "osint_cache"),
))

BASE_URL = "https://api.hunter.how"

DEFAULT_FIELDS = (
    "ip,port,domain,protocol,transport_protocol,web_title,"
    "country,province,city,url,asn,as_org,as_name,"
    "status_code,cert,os,header,header_server,banner,product,updated_at,body"
)


# ── Public entry point ────────────────────────────────────────────────────────

def run_hunter(assets: List[Dict], out_dir: Path) -> List[Dict]:
    """
    Enrich assets with Hunter.how infrastructure intelligence.
    Queries by domain (hostname) or IP and injects hunter_findings into each asset.
    """
    api_key = os.environ.get("HUNTER_API_KEY", "").strip()
    if not api_key:
        print("  [!] HUNTER_API_KEY not configured — skipping Hunter.how recon")
        return assets

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    session.headers.update({"User-Agent": "Inventa/2.0"})

    seen: set = set()

    for asset in assets:
        query, label = _build_query(asset)
        if not query or query in seen:
            continue
        seen.add(query)

        findings = _search(query, api_key, session)
        if findings:
            asset["hunter_findings"] = findings
            total = findings.get("total", 0)
            returned = len(findings.get("results", []))
            print(
                f"  [+] {label} — Hunter.how: "
                f"{total} result(s) found, {returned} returned"
            )

    return assets


# ── Query builder ─────────────────────────────────────────────────────────────

def _build_query(asset: Dict[str, Any]):
    """Return (query_string, human_label) for the asset, or (None, None)."""
    domain = _get_domain(asset)
    if domain:
        return f'domain="{domain}"', domain

    ip = asset.get("ip", "").strip()
    if ip and not _is_private_ip(ip):
        return f'ip="{ip}"', ip

    return None, None


# ── API call ──────────────────────────────────────────────────────────────────

def _search(
    query: str,
    api_key: str,
    session: requests.Session,
    page: int = 1,
    page_size: int = 10,  # valid: 10, 20, 50, 100, 1000
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    fields: str = DEFAULT_FIELDS,
) -> Optional[Dict[str, Any]]:
    cache_key = f"hunterhow:search:{query}:{page}:{page_size}"

    def fetch():
        encoded_query = base64.urlsafe_b64encode(query.encode("utf-8")).decode("ascii")
        url = (
            "%s/search?api-key=%s&query=%s&page=%d&page_size=%d"
            "&start_time=%s&end_time=%s&fields=%s"
        ) % (
            BASE_URL, api_key, encoded_query, page, page_size,
            start_time or "", end_time or "", fields,
        )
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code in (401, 403, 429):
            return None
        resp.raise_for_status()
        data = resp.json()

        # hunter.how wraps results in {"code": 200, "data": {...}}
        if isinstance(data, dict) and "data" in data:
            inner = data["data"]
        else:
            inner = data

        results = inner.get("list") or inner.get("results") or []
        total = inner.get("total") or len(results)

        return {
            "query":   query,
            "total":   total,
            "page":    page,
            "results": [_normalise_result(r) for r in results],
        }

    return _cached(cache_key, fetch)


def _normalise_result(r: Dict[str, Any]) -> Dict[str, Any]:
    """Map hunter.how result fields to a clean dict."""
    return {
        "ip":                 r.get("ip"),
        "port":               r.get("port"),
        "domain":             r.get("domain"),
        "protocol":           r.get("protocol"),
        "transport_protocol": r.get("transport_protocol"),
        "web_title":          r.get("web_title"),
        "country":            r.get("country"),
        "province":           r.get("province"),
        "city":               r.get("city"),
        "url":                r.get("url"),
        "asn":                r.get("asn"),
        "as_org":             r.get("as_org"),
        "as_name":            r.get("as_name"),
        "status_code":        r.get("status_code"),
        "os":                 r.get("os"),
        "header_server":      r.get("header_server"),
        "product":            r.get("product"),
        "banner":             r.get("banner"),
        "cert":               r.get("cert"),
        "updated_at":         r.get("updated_at"),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_domain(asset: Dict[str, Any]) -> Optional[str]:
    for key in ("hostname", "fqdn", "domain", "endpoint"):
        val = asset.get(key)
        if val and isinstance(val, str) and "." in val and " " not in val:
            val = val.strip().lower()
            if not _is_ip(val) and not val.endswith((".local", ".lan", ".internal")):
                return val
    return None


def _is_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_private_ip(value: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return True


def _cache_path(key: str) -> Path:
    digest = hashlib.sha256(key.encode()).hexdigest()
    return CACHE_DIR / f"{digest}.json"


def _cached(key: str, fetch_fn):
    path = _cache_path(key)
    if path.exists():
        age = time.time() - path.stat().st_mtime
        if age <= CACHE_TTL:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass
    try:
        result = fetch_fn()
        path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        return result
    except requests.exceptions.RequestException as e:
        print(f"  [!] Hunter.how request failed ({key}): {e}")
        return None
    except Exception as e:
        print(f"  [!] Hunter.how processing error ({key}): {e}")
        return None
