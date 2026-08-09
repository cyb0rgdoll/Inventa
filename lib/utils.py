"""Utility functions for Inventa."""

import ipaddress
from pathlib import Path
from lib.colors import warn


def load_lines(filepath: str) -> list:
    """Load lines from a file, skipping comments and empty lines."""
    if not filepath:
        return []
    try:
        lines = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    lines.append(line)
        return lines
    except FileNotFoundError:
        return []
    except Exception as e:
        print(warn(f"Failed to read {filepath}: {e}"))
        return []


def merge_unique(items: list) -> list:
    """Remove duplicates while preserving order."""
    merged = []
    seen = set()
    for item in items:
        key = str(item).strip()
        if key and key not in seen:
            seen.add(key)
            merged.append(item)
    return merged


def load_cidrs(cidr_values: list) -> list:
    """Convert CIDR strings to IPv4Network objects."""
    cidrs = []
    for value in cidr_values or []:
        try:
            cidrs.append(ipaddress.IPv4Network(value, strict=False))
        except ValueError as e:
            print(warn(f"Invalid CIDR skipped: {value}"))
    return cidrs


def is_domain(target: str) -> bool:
    """Check if target is a domain (not an IP)."""
    value = str(target).strip()
    if not value or "." not in value or " " in value:
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        return True


def ensure_dir(path: Path) -> Path:
    """Create directory if it doesn't exist."""
    path.mkdir(parents=True, exist_ok=True)
    return path
