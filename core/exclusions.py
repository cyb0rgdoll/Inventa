"""Scope exclusion rules for safer command-line scans."""

from __future__ import annotations

import fnmatch
import ipaddress
from pathlib import Path
from typing import Dict, Iterable, List
from urllib.parse import urlparse


class ExclusionRules:
    def __init__(self, patterns: Iterable[str] = ()):
        self.patterns = [p.strip() for p in patterns if p and p.strip() and not p.strip().startswith("#")]
        self.networks = []
        self.ip_addresses = set()
        self.text_patterns = []

        for pattern in self.patterns:
            try:
                if "/" in pattern:
                    self.networks.append(ipaddress.ip_network(pattern, strict=False))
                    continue
                self.ip_addresses.add(str(ipaddress.ip_address(pattern)))
                continue
            except ValueError:
                self.text_patterns.append(pattern.lower())

    def is_excluded(self, value: str) -> bool:
        host = _extract_host(value)
        if not host:
            return False

        if "/" in host:
            try:
                target_network = ipaddress.ip_network(host, strict=False)
                return any(target_network.overlaps(network) for network in self.networks)
            except ValueError:
                pass

        try:
            ip = ipaddress.ip_address(host)
            if str(ip) in self.ip_addresses:
                return True
            return any(ip in network for network in self.networks)
        except ValueError:
            host_lower = host.lower()
            return any(_matches_text_pattern(pattern, host_lower) for pattern in self.text_patterns)

    def filter_targets(self, targets: Iterable[str]) -> List[str]:
        return [target for target in targets if not self.is_excluded(str(target))]

    def filter_assets(self, assets: Iterable[Dict]) -> List[Dict]:
        return [asset for asset in assets if not self.asset_excluded(asset)]

    def asset_excluded(self, asset: Dict) -> bool:
        candidates = [
            asset.get("ip"),
            asset.get("public_ip"),
            asset.get("hostname"),
            asset.get("fqdn"),
            asset.get("domain"),
            asset.get("endpoint"),
            asset.get("name"),
            asset.get("resource_id"),
        ]
        return any(self.is_excluded(str(value)) for value in candidates if value)


def load_exclusions(exclude_file: str | None) -> ExclusionRules:
    if not exclude_file:
        return ExclusionRules()
    path = Path(exclude_file)
    if not path.exists():
        raise FileNotFoundError(f"Exclude file not found: {exclude_file}")
    return ExclusionRules(path.read_text(encoding="utf-8").splitlines())


def _extract_host(value: str) -> str:
    value = str(value).strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or value
    return value.split("/")[0] if "/" not in value or _looks_like_url_path(value) else value


def _looks_like_url_path(value: str) -> bool:
    return value.startswith("/") or value.count("/") > 1


def _matches_text_pattern(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) or host == pattern[2:]
    if "*" in pattern:
        return fnmatch.fnmatch(host, pattern)
    return host == pattern
