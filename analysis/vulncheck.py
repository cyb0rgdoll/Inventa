"""
Vulnerability Correlation Module
CVE matching against discovered assets based on service versions.

Lookup chain: NVD 2.0 → VulDB (advancedsearch) → cve.circl.lu
"""

import os
import re
import threading
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
from urllib.parse import quote


_NVD_API_KEY: Optional[str] = os.environ.get("NVD_API_KEY")
_VULDB_API_KEY: Optional[str] = os.environ.get("VULDB_API_KEY")
_NVD_REQUEST_TIMEOUT = 20
_NVD_RATE_DELAY = 0.6 if _NVD_API_KEY else 6.0
_VULDB_RATE_LOCK = threading.Lock()
_VULDB_LAST_CALL = 0.0


def _vuldb_rate_wait():
    """VulDB enforces max 30 req/min — wait at least 2s between calls."""
    global _VULDB_LAST_CALL
    with _VULDB_RATE_LOCK:
        now = time.time()
        elapsed = now - _VULDB_LAST_CALL
        if elapsed < 2.0:
            time.sleep(2.0 - elapsed)
        _VULDB_LAST_CALL = time.time()


def correlate_vulnerabilities(assets: List[Dict]) -> List[Dict]:
    queries = []
    for asset in assets:
        for port_info in asset.get('ports', []):
            service = port_info.get('service')
            version = port_info.get('version')
            if service and version:
                queries.append((asset, port_info, service, version))

        os_info = asset.get('os')
        if os_info:
            queries.append((asset, None, 'os', os_info))

    if not queries:
        return assets

    max_workers = 10 if _NVD_API_KEY else 2
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_meta = {
            executor.submit(query_cve_database, service, version): (asset, port_info)
            for asset, port_info, service, version in queries
        }

        for future in as_completed(future_to_meta):
            asset, port_info = future_to_meta[future]
            try:
                cves = future.result()
                if cves:
                    if 'vulnerabilities' not in asset:
                        asset['vulnerabilities'] = []
                    asset['vulnerabilities'].extend(cves)
                    if port_info:
                        print(f"  [!] {asset.get('ip')}:{port_info.get('port')} - Found {len(cves)} potential CVE(s)")
            except Exception:
                pass

    for asset in assets:
        if 'vulnerabilities' in asset:
            asset['vulnerability_count'] = len(asset['vulnerabilities'])

    return assets


def query_cve_database(product: str, version: str) -> List[Dict]:
    version_clean = extract_version_number(version)
    if not version_clean:
        return []

    cves = _query_nvd(product, version_clean)
    if cves:
        return cves

    cves = _query_vuldb(product, version_clean)
    if cves:
        return cves

    return _query_circl(product, version_clean)


def _query_nvd(product: str, version: str) -> List[Dict]:
    try:
        keyword = f"{product} {version}"
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 10,
        }
        headers = {"User-Agent": "Inventa/2.0"}
        if _NVD_API_KEY:
            headers["apiKey"] = _NVD_API_KEY

        time.sleep(_NVD_RATE_DELAY)

        response = requests.get(url, params=params, headers=headers, timeout=_NVD_REQUEST_TIMEOUT)
        if response.status_code == 403:
            return []
        response.raise_for_status()
        data = response.json()

        cves = []
        for item in (data.get("vulnerabilities") or [])[:5]:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "Unknown")

            descriptions = cve_data.get("descriptions", [])
            summary = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                "",
            )

            metrics = cve_data.get("metrics", {})
            cvss_score = None
            severity = None
            for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(metric_key) or []
                if entries:
                    cvss_data = entries[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity")
                    break

            cves.append({
                'cve_id': cve_id,
                'summary': summary[:200],
                'cvss': cvss_score,
                'severity': severity,
                'published': cve_data.get("published"),
                'source': 'nvd',
            })

        return cves

    except requests.exceptions.RequestException:
        return []
    except Exception as e:
        print(f"  [!] NVD query failed for {product} {version}: {e}")
        return []


def _query_vuldb(product: str, version: str) -> List[Dict]:
    if not _VULDB_API_KEY:
        return []
    try:
        _vuldb_rate_wait()

        url = "https://vuldb.com/api"
        post_data = {
            "advancedsearch": f"product:{quote(product)},version:{quote(version)}",
            "details": "1",
        }
        response = requests.post(
            url,
            headers={"X-VulDB-ApiKey": _VULDB_API_KEY},
            data=post_data,
            timeout=15,
        )
        if response.status_code in (204, 401, 402, 403, 404, 405, 429):
            return []
        response.raise_for_status()
        data = response.json()

        resp_header = data.get("response", {})
        if str(resp_header.get("status")) == "204":
            return []

        cves = []
        for entry in (data.get("result") or [])[:5]:
            source = entry.get("source", {}) or {}
            advisory = entry.get("advisory", {}) or {}
            vulnerability = entry.get("vulnerability", {}) or {}
            exploit = entry.get("exploit", {}) or {}
            entry_meta = entry.get("entry", {}) or {}

            cve_id = (source.get("cve", {}) or {}).get("id")
            if not cve_id:
                continue

            score, severity = _extract_vuldb_cvss(vulnerability)

            timestamp = entry_meta.get("timestamp", {}) or {}
            risk = vulnerability.get("risk", {}) or {}
            kev = exploit.get("kev", {}) or {}

            cves.append({
                'cve_id': cve_id,
                'summary': (source.get("cve", {}) or {}).get("summary", "")[:200]
                           or (entry_meta.get("title") or "")[:200],
                'cvss': score,
                'severity': severity,
                'published': advisory.get("date") or timestamp.get("create"),
                'source': 'vuldb',
                'vuldb_id': entry_meta.get("id"),
                'exploit_available': str(exploit.get("availability")) == "1",
                'risk': risk.get("name") if isinstance(risk, dict) else risk,
                'kev': bool(kev),
                'epss_score': (exploit.get("epss", {}) or {}).get("score"),
            })

        return cves

    except requests.exceptions.RequestException:
        return []
    except Exception as e:
        print(f"  [!] VulDB query failed for {product} {version}: {e}")
        return []


def _extract_vuldb_cvss(vulnerability: Dict) -> tuple:
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


def _query_circl(product: str, version: str) -> List[Dict]:
    try:
        search_term = f"{product} {version}"
        url = f"https://cve.circl.lu/api/search/{quote(search_term)}"
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return []

        data = response.json()
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("results") or data.get("cves") or []
        else:
            items = []

        if not isinstance(items, list):
            print(f"  [!] CIRCL returned unexpected response shape for {product} {version}")
            return []

        cves = []
        for item in items[:5]:
            cves.append({
                'cve_id': item.get('id', 'Unknown'),
                'summary': item.get('summary', '')[:200],
                'cvss': item.get('cvss'),
                'severity': None,
                'published': item.get('Published'),
                'source': 'circl',
            })
        return cves

    except requests.exceptions.RequestException:
        return []
    except Exception as e:
        print(f"  [!] CIRCL CVE query failed: {e}")
        return []


def extract_version_number(version_string: str) -> str:
    if not version_string:
        return None

    match = re.search(r'(\d+(?:\.\d+)*)', version_string)

    if match:
        return match.group(1)

    return None
