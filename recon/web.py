"""
Web Inspector Module
Inspects web-accessible assets: HTTP headers, cookies, forms, external scripts,
linked domains, and technology fingerprints.
Inspired by inSp3ctor (https://github.com/brianwarehime/inSp3ctor)

Runs the real inSp3ctor CLI automatically if cloned into tools/inSp3ctor/.
Falls back to a native Python implementation otherwise.
"""

from __future__ import annotations

import shutil
import subprocess
import warnings
import json
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import requests

from modules.platform_compat import python_executable
from bs4 import BeautifulSoup

# NOTE: TLS certificate verification is intentionally disabled for the probes in
# this module. Inventa inspects hosts that frequently present self-signed,
# expired, or hostname-mismatched certificates, and the goal here is to observe
# what is exposed, not to establish a trusted channel. Because verification is
# off, responses fetched here are treated as UNTRUSTED evidence only — never as
# a source of truth or executable content. Do not reuse this pattern for
# requests whose result is trusted or acted upon.
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

REQUEST_TIMEOUT = 10

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "access-control-allow-origin",
]

_STANDARD_HEADERS = {
    "content-type", "content-length", "content-encoding", "date", "expires",
    "cache-control", "last-modified", "etag", "connection", "keep-alive",
    "transfer-encoding", "vary", "accept-ranges",
}

TECHNOLOGY_SIGNATURES: Dict[str, List[str]] = {
    "WordPress":   ["wp-content", "wp-includes", "WordPress"],
    "Drupal":      ["Drupal", "/sites/default/"],
    "Joomla":      ["Joomla", "/components/com_"],
    "React":       ["react.js", "react.min.js"],
    "Angular":     ["angular.js", "ng-version", "angular.min.js"],
    "Vue.js":      ["vue.js", "vue.min.js"],
    "jQuery":      ["jquery.js", "jquery.min.js"],
    "Bootstrap":   ["bootstrap.js", "bootstrap.min.css"],
    "Laravel":     ["laravel_session", "XSRF-TOKEN"],
    "Django":      ["csrfmiddlewaretoken"],
    "ASP.NET":     ["__VIEWSTATE", "ASP.NET_SessionId"],
    "PHP":         ["PHPSESSID"],
    "Apache":      ["Apache"],
    "Nginx":       ["nginx"],
    "IIS":         ["IIS"],
    "Cloudflare":  ["cf-ray", "cloudflare"],
    "AWS ALB":     ["awsalb", "AWSALB"],
    "Varnish":     ["X-Varnish"],
}


# ── Public entry point ────────────────────────────────────────────────────────

def run_web_inspector(assets: List[Dict], out_dir: Path) -> List[Dict]:
    """
    Inspect web-accessible assets and write 'web_inspection' into each asset dict.
    """
    _try_external_tool(assets, out_dir)

    session = requests.Session()
    session.headers.update({"User-Agent": "Inventa/2.0 WebInspector"})

    for asset in assets:
        urls = _get_web_urls(asset)
        if not urls:
            continue

        inspection: Dict[str, Dict] = {}
        for url in urls:
            result = inspect_url(url, session)
            if result:
                nikto_result = _run_nikto(url, out_dir)
                if nikto_result:
                    result["nikto"] = nikto_result
                inspection[url] = result

        if inspection:
            asset["web_inspection"] = inspection
            technologies: Set[str] = set()
            for r in inspection.values():
                technologies.update(r.get("technologies", []))
            label = asset.get("hostname") or asset.get("ip") or "asset"
            tech_str = f", tech: {', '.join(sorted(technologies))}" if technologies else ""
            print(f"  [+] {label} — {len(inspection)} web endpoint(s) inspected{tech_str}")

    return assets


# ── Core inspector ────────────────────────────────────────────────────────────

def inspect_url(url: str, session: requests.Session) -> Optional[Dict]:
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=False)
    except requests.exceptions.RequestException:
        return None

    result: Dict = {
        "url": url,
        "status_code": resp.status_code,
        "final_url": resp.url,
        "headers": {k.lower(): v for k, v in resp.headers.items()},
        "security_headers": _extract_security_headers(resp.headers),
        "missing_security_headers": _missing_security_headers(resp.headers),
        "cookies": _extract_cookies(resp.cookies),
        "server": resp.headers.get("Server") or resp.headers.get("X-Powered-By"),
        "technologies": [],
        "forms": [],
        "external_links": [],
        "external_scripts": [],
        "interesting_headers": [],
    }

    header_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
    cookie_str = " ".join(resp.cookies.keys())
    detected: Set[str] = set()

    for tech, sigs in TECHNOLOGY_SIGNATURES.items():
        if any(sig.lower() in header_str.lower() or sig.lower() in cookie_str.lower() for sig in sigs):
            detected.add(tech)

    if "text/html" in resp.headers.get("Content-Type", ""):
        soup = BeautifulSoup(resp.text, "html.parser")
        base_domain = urlparse(url).netloc
        body_text = str(soup)

        for form in soup.find_all("form"):
            result["forms"].append({
                "action": form.get("action"),
                "method": (form.get("method") or "get").upper(),
                "inputs": [
                    {"name": inp.get("name"), "type": inp.get("type", "text")}
                    for inp in form.find_all("input")
                    if inp.get("name")
                ],
            })

        seen_ext: Set[str] = set()
        for script in soup.find_all("script", src=True):
            src = script["src"]
            abs_src = urljoin(url, src)
            ext_domain = urlparse(abs_src).netloc
            if ext_domain and ext_domain != base_domain and ext_domain not in seen_ext:
                seen_ext.add(ext_domain)
                result["external_scripts"].append(abs_src)
            for tech, sigs in TECHNOLOGY_SIGNATURES.items():
                if any(sig.lower() in src.lower() for sig in sigs):
                    detected.add(tech)

        seen_links: Set[str] = set()
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if href.startswith(("http://", "https://")):
                ext = urlparse(href).netloc
                if ext and ext != base_domain and ext not in seen_links:
                    seen_links.add(ext)
                    result["external_links"].append(ext)

        for tech, sigs in TECHNOLOGY_SIGNATURES.items():
            if any(sig in body_text for sig in sigs):
                detected.add(tech)

    for key, val in resp.headers.items():
        if key.lower() not in _STANDARD_HEADERS:
            result["interesting_headers"].append(f"{key}: {val}")

    result["technologies"] = sorted(detected)
    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_web_urls(asset: Dict) -> List[str]:
    explicit_urls = []
    if asset.get("url"):
        explicit_urls.append(str(asset["url"]))
    explicit_urls.extend(str(url) for url in asset.get("urls", []) if url)
    if explicit_urls:
        return list(dict.fromkeys(explicit_urls))[:5]

    host = asset.get("hostname") or asset.get("fqdn") or asset.get("ip") or asset.get("public_ip")
    if not host:
        return []

    urls: List[str] = []
    for port_info in asset.get("ports", []):
        port = str(port_info.get("port", ""))
        service = str(port_info.get("service", "")).lower()
        if port in ("80", "8080") or "http" in service and "https" not in service:
            prefix = f"http://{host}" if port == "80" else f"http://{host}:{port}"
            urls.append(prefix)
        elif port in ("443", "8443") or "https" in service:
            prefix = f"https://{host}" if port == "443" else f"https://{host}:{port}"
            urls.append(prefix)

    if not urls:
        for svc in [str(s).lower() for s in asset.get("services", [])]:
            if svc in ("http",):
                urls.append(f"http://{host}")
            elif svc in ("https",):
                urls.append(f"https://{host}")

    return urls[:5]


def _extract_security_headers(headers) -> Dict[str, str]:
    norm = {k.lower(): v for k, v in headers.items()}
    return {h: norm[h] for h in SECURITY_HEADERS if h in norm}


def _missing_security_headers(headers) -> List[str]:
    norm = {k.lower() for k in headers.keys()}
    return [h for h in SECURITY_HEADERS if h not in norm]


def _extract_cookies(cookies) -> List[Dict]:
    result = []
    for c in cookies:
        result.append({
            "name": c.name,
            "value": (c.value[:20] + "...") if len(c.value) > 20 else c.value,
            "secure": c.secure,
            "http_only": bool(getattr(c, "_rest", {}).get("HttpOnly")),
            "domain": c.domain,
            "path": c.path,
        })
    return result


def _try_external_tool(assets: List[Dict], out_dir: Path) -> None:
    tool_path = Path(__file__).parent.parent / "tools" / "inSp3ctor" / "inspector.py"
    if not tool_path.exists():
        return

    urls: List[str] = []
    for asset in assets:
        urls.extend(_get_web_urls(asset))
    if not urls:
        return

    targets_file = out_dir / "inspector_targets.txt"
    targets_file.write_text("\n".join(urls), encoding="utf-8")

    try:
        subprocess.run(
            [python_executable(), str(tool_path), "-l", str(targets_file)],
            capture_output=True, text=True, timeout=120,
        )
        print(f"  [✓] inSp3ctor (external) targets written: {targets_file}")
    except Exception:
        pass


def _run_nikto(url: str, out_dir: Path) -> Optional[Dict]:
    if not shutil.which("nikto"):
        return None

    out_dir.mkdir(parents=True, exist_ok=True)
    slug = _slugify_url(url)
    output_file = out_dir / f"nikto_{slug}.json"
    cmd = [
        "nikto",
        "-host", url,
        "-Format", "json",
        "-output", str(output_file),
        "-nointeractive",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0 and not output_file.exists():
            stderr = result.stderr.strip()
            stdout = result.stdout.strip()
            details = stderr or stdout or "no diagnostic output"
            return {"status": "error", "message": details[:300]}
        if not output_file.exists():
            return None
        return _parse_nikto_output(output_file)
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "nikto timed out after 5 minutes"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def _parse_nikto_output(output_file: Path) -> Optional[Dict]:
    try:
        raw = output_file.read_text(encoding="utf-8", errors="ignore").strip()
    except Exception:
        return None

    if not raw:
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"status": "unknown", "raw": raw[:2000]}

    findings = []
    items = []
    if isinstance(data, dict):
        items = data.get("vulnerabilities") or data.get("findings") or data.get("items") or []
        if not items and "nikto" in data and isinstance(data["nikto"], dict):
            items = data["nikto"].get("items") or []

    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            findings.append({
                "id": item.get("id") or item.get("msgid"),
                "message": item.get("msg") or item.get("message") or item.get("description"),
                "uri": item.get("uri") or item.get("url"),
                "references": item.get("references") or item.get("ref") or [],
            })

    return {
        "status": "ok",
        "finding_count": len(findings),
        "findings": findings[:50],
        "raw": data,
    }


def _slugify_url(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.replace(":", "_")
    path = (parsed.path or "/").strip("/").replace("/", "_") or "root"
    return f"{parsed.scheme}_{host}_{path}"
