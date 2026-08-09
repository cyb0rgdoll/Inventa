"""
Scope Management Module
Loads and validates CIDR ranges to ensure only authorised targets are scanned
"""

import ipaddress
import socket
from typing import List


def load_scope(scope_file: str) -> List[ipaddress.IPv4Network]:
    """
    Load authorised CIDR ranges from a scope file.
    """
    cidrs = []

    try:
        f = open(scope_file, "r", encoding="utf-8")
    except FileNotFoundError:
        raise SystemExit(
            f"[!] Scope file not found: {scope_file}\n"
            f"    Create it (one authorised CIDR per line) or set SCOPE_FILE."
        )

    with f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            try:
                cidr = ipaddress.IPv4Network(line, strict=False)
                cidrs.append(cidr)
            except ValueError as e:
                print(f"[!] Invalid CIDR in scope file: {line} ({e})")

    if not cidrs:
        raise ValueError("No valid CIDR ranges found in scope file")

    return cidrs


def validate_target(target: str, scope_cidrs: List[ipaddress.IPv4Network]) -> bool:
    """
    Validate that a target IP or resolvable hostname is within authorised scope.
    """
    try:
        ip = ipaddress.IPv4Address(target)
        return any(ip in cidr for cidr in scope_cidrs)
    except ipaddress.AddressValueError:
        pass

    try:
        resolved_ips = {
            ipaddress.IPv4Address(info[4][0])
            for info in socket.getaddrinfo(target, None, family=socket.AF_INET)
        }
        return bool(resolved_ips) and all(
            any(ip in cidr for cidr in scope_cidrs) for ip in resolved_ips
        )
    except Exception:
        return False


def validate_discovered_ip(ip_str: str, scope_cidrs: List[ipaddress.IPv4Network]) -> bool:
    """
    Validate a discovered IP address against scope.
    """
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return any(ip in cidr for cidr in scope_cidrs)
    except (ipaddress.AddressValueError, ValueError):
        return False