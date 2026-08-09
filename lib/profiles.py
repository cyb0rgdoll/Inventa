"""Scan profile management for saving and reusing scan configurations."""

import json
import argparse
from pathlib import Path
from typing import Optional, List


def get_profiles_dir() -> Path:
    """Get the profiles directory (~/.inventa/profiles/)."""
    profiles_dir = Path.home() / ".inventa" / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    return profiles_dir


def save_profile(name: str, args: argparse.Namespace) -> bool:
    """Save a scan configuration as a reusable profile.

    Args:
        name: Profile name
        args: argparse.Namespace with scan configuration

    Returns:
        True if successful
    """
    profiles_dir = get_profiles_dir()
    profile_path = profiles_dir / f"{name}.json"

    # Extract scan-related attributes
    profile_data = {
        "scope": getattr(args, 'scope', ''),
        "targets_file": getattr(args, 'targets_file', ''),
        "profile": getattr(args, 'profile', 'medium'),
        "banner_grab": getattr(args, 'banner_grab', False),
        "fingerprint": getattr(args, 'fingerprint', False),
        "osint": getattr(args, 'osint', False),
        "passive_dns": getattr(args, 'passive_dns', False),
        "cloud_enum": getattr(args, 'cloud_enum', False),
        "cloud_provider": getattr(args, 'cloud_provider', 'aws'),
        "subdomain_enum": getattr(args, 'subdomain_enum', False),
        "web_inspect": getattr(args, 'web_inspect', False),
        "vuln_check": getattr(args, 'vuln_check', False),
        "tls": getattr(args, 'tls', False),
    }

    try:
        profile_path.write_text(json.dumps(profile_data, indent=2))
        return True
    except Exception:
        return False


def load_profile(name: str) -> Optional[dict]:
    """Load a saved profile.

    Args:
        name: Profile name (without .json)

    Returns:
        Profile data dict or None if not found
    """
    profiles_dir = get_profiles_dir()
    profile_path = profiles_dir / f"{name}.json"

    if not profile_path.exists():
        return None

    try:
        return json.loads(profile_path.read_text())
    except Exception:
        return None


def list_profiles() -> List[str]:
    """List all saved profiles.

    Returns:
        List of profile names (without .json)
    """
    profiles_dir = get_profiles_dir()
    return [p.stem for p in profiles_dir.glob("*.json")]


def delete_profile(name: str) -> bool:
    """Delete a saved profile.

    Args:
        name: Profile name

    Returns:
        True if successful
    """
    profiles_dir = get_profiles_dir()
    profile_path = profiles_dir / f"{name}.json"

    if not profile_path.exists():
        return False

    try:
        profile_path.unlink()
        return True
    except Exception:
        return False


def apply_profile(args: argparse.Namespace, profile_name: str) -> bool:
    """Apply a saved profile to args namespace.

    Args:
        args: argparse.Namespace to update
        profile_name: Profile name to apply

    Returns:
        True if successful
    """
    profile = load_profile(profile_name)
    if not profile:
        return False

    for key, value in profile.items():
        setattr(args, key, value)
    return True
