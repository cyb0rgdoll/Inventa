import sys
from argparse import Namespace

from inventa import parse_args, run_inventa


def test_domain_workflow_short_flags(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["inventa.py", "-d", "example.com", "-W", "domain", "-e", "*.old.example.com"])

    args = parse_args()

    assert args.domain == ["example.com"]
    assert args.domain_recon is True
    assert args.subdomain_enum is True
    assert args.no_active is True
    assert args.exclude_list == "*.old.example.com"


def test_cloud_workflow_provider_alias(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["inventa.py", "-W", "cloud", "--provider", "azure"])

    args = parse_args()

    assert args.cloud_enum is True
    assert args.no_active is True
    assert args.cloud_provider == "azure"


def test_cloudscraper_alias(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["inventa.py", "-d", "example.com", "--cloudscraper"])

    args = parse_args()

    assert args.cloud_scraper is True
    assert args.domain == ["example.com"]
    assert args.domain_recon is False
    assert args.no_active is True


def test_easy_domain_command(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["inventa.py", "domain", "example.com"])

    args = parse_args()

    assert args.domain == ["example.com"]
    assert args.domain_recon is True
    assert args.subdomain_enum is True
    assert args.no_active is True


def test_easy_cloudscraper_command(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["inventa.py", "cloudscraper", "example.com"])

    args = parse_args()

    assert args.domain == ["example.com"]
    assert args.cloud_scraper is True
    assert args.no_active is True
    assert args.domain_recon is False


def test_easy_web_command_is_lightweight(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["inventa.py", "web", "example.com"])

    args = parse_args()

    assert args.domain == ["example.com"]
    assert args.web_inspect is True
    assert args.zgrab2 is True
    assert args.web_suite is False
    assert args.domain_recon is False
    assert args.no_active is True


def test_easy_cloud_provider_command(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["inventa.py", "cloud", "all"])

    args = parse_args()

    assert args.cloud_enum is True
    assert args.cloud_provider == "all"
    assert args.no_active is True


def test_easy_examples_command(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["inventa.py", "examples"])

    args = parse_args()

    assert args.examples is True


def test_subdomain_enum_receives_domain_targets(monkeypatch, tmp_path):
    captured = {}

    monkeypatch.setattr("inventa.load_scope", lambda _: [])
    monkeypatch.setattr("inventa.validate_target", lambda target, scope: False)
    monkeypatch.setattr("inventa.classify_assets", lambda assets: assets)

    def fake_subdomain_enum(targets, assets, scope_cidrs, out_dir):
        captured["targets"] = targets
        return []

    monkeypatch.setattr("recon.subdomain.run_subdomain_enum", fake_subdomain_enum)

    args = Namespace(
        out=str(tmp_path),
        scope=None,
        scope_cidr=[],
        targets_file=None,
        target=[],
        websites_file=None,
        website=[],
        domain=["example.com"],
        exclude_file=None,
        exclude_list="",
        cloud_enum=False,
        passive_dns=False,
        cloud_enum_osint=False,
        vhostscan=False,
        masscan=False,
        domain_recon=False,
        striker=False,
        reconspider=False,
        zmap=False,
        no_active=True,
        zgrab2=False,
        smap=False,
        subdomain_enum=True,
        web_suite=False,
        web_inspect=False,
        banner_grab=False,
        fingerprint=False,
        vuln_check=False,
        tls=False,
        osint=False,
        cloud_scraper=False,
        hunter=False,
        topology=False,
        compliance=False,
        history=False,
        report="none",
        profile="low",
    )

    run_inventa(args)

    assert captured["targets"] == ["example.com"]
