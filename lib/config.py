"""Centralized configuration and workflow definitions."""

import argparse
from pathlib import Path

WORKFLOWS = {
    "quick": {
        "description": "Fast discovery on common ports (low profile)",
        "profile": "low",
        "banner_grab": False,
        "fingerprint": False,
        "passive_dns": False,
        "cloud_enum": False,
    },
    "standard": {
        "description": "Balanced scan with service banners & OS fingerprinting",
        "profile": "medium",
        "banner_grab": True,
        "fingerprint": True,
        "passive_dns": True,
        "cloud_enum": False,
    },
    "cloud": {
        "description": "AWS/Azure/GCP account inventory via configured CLIs",
        "profile": "low",
        "cloud_enum": True,
        "no_active": True,
    },
    "domain": {
        "description": "Domain & subdomain reconnaissance (passive)",
        "profile": "low",
        "domain_recon": True,
        "subdomain_enum": True,
        "no_active": True,
    },
    "web": {
        "description": "Website/domain inspection with web tooling",
        "profile": "low",
        "web_suite": True,
        "web_inspect": True,
        "zgrab2": True,
        "no_active": True,
    },
}

API_KEYS = [
    ("Shodan", "SHODAN_API_KEY"),
    ("Censys ID", "CENSYS_API_ID"),
    ("BuiltWith", "BUILTWITH_API_KEY"),
    ("VirusTotal", "VIRUSTOTAL_API_KEY"),
    ("SecurityTrails", "SECURITYTRAILS_API_KEY"),
    ("Host.io", "HOSTIO_API_KEY"),
    ("IPInfo", "IPINFO_API_KEY"),
    ("NVD", "NVD_API_KEY"),
]


def apply_workflow(args, workflow: str) -> None:
    """Apply workflow settings to args."""
    if workflow not in WORKFLOWS:
        return

    settings = WORKFLOWS[workflow]
    for key, value in settings.items():
        setattr(args, key, value)


def make_scan_args(scope, targets_file, out, profile="low", **flags) -> argparse.Namespace:
    """Create scan arguments namespace with defaults."""
    defaults = {
        "scope": scope,
        "targets_file": targets_file,
        "out": str(out),
        "profile": profile,
        "banner_grab": False,
        "fingerprint": False,
        "vuln_check": False,
        "tls": False,
        "topology": False,
        "compliance": False,
        "osint": False,
        "ai": False,
        "history": False,
        "no_active": False,
        "passive_dns": False,
        "cloud_enum": False,
        "cloud_scraper": False,
        "web_inspect": False,
        "subdomain_enum": False,
        "smap": False,
        "masscan": False,
        "zmap": False,
        "zgrab2": False,
        "hunter": False,
        "domain_recon": False,
        "striker": False,
        "reconspider": False,
        "web_suite": False,
        "vulscan": False,
        "vulners": False,
        "zgrab2_module": "http",
        "websites_file": None,
        "report": "both",
    }
    defaults.update(flags)
    return argparse.Namespace(**defaults)


def get_config_paths(script_dir: Path) -> tuple:
    """Get standard config file paths."""
    import os
    scope_file = os.environ.get("SCOPE_FILE", str(script_dir / "scope.txt"))
    targets_file = os.environ.get("TARGETS_FILE", str(script_dir / "targets.txt"))
    results_dir = Path(os.environ.get("RESULTS_DIR", str(script_dir / "results")))
    return scope_file, targets_file, results_dir


EXAMPLES = """Quick Commands
===============

Health check:
  python3 inventa.py doctor

Domain recon:
  python3 inventa.py domain example.com

Website inspection:
  python3 inventa.py web example.com

Cloud inventory:
  python3 inventa.py cloud aws
  python3 inventa.py cloud azure

Scoped active scan:
  python3 inventa.py -s scope.txt -t targets.txt -W quick
  python3 inventa.py -s scope.txt -t targets.txt -W standard

With exclusions:
  python3 inventa.py -s scope.txt -t targets.txt --exclude exclude.txt
"""
