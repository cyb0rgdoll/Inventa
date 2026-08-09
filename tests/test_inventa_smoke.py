import argparse
import json

from inventa import run_inventa


def test_run_inventa_writes_json_for_passive_no_asset_run(tmp_path, capsys):
    scope_file = tmp_path / "scope.txt"
    targets_file = tmp_path / "targets.txt"
    out_dir = tmp_path / "results"

    scope_file.write_text("192.168.1.0/24\n", encoding="utf-8")
    targets_file.write_text("192.168.1.50\n", encoding="utf-8")

    args = argparse.Namespace(
        scope=str(scope_file),
        targets_file=str(targets_file),
        profile="low",
        out=str(out_dir),
        report="none",
        banner_grab=False,
        fingerprint=False,
        vuln_check=False,
        tls=False,
        topology=False,
        compliance=False,
        osint=False,
        passive_dns=False,
        cloud_enum=False,
        ai=False,
        history=False,
        no_active=True,
        cloud_scraper=False,
        web_inspect=False,
        subdomain_enum=False,
        smap=False,
        masscan=False,
        zmap=False,
        zgrab2=False,
        zgrab2_module="http",
        domain_recon=False,
        striker=False,
        reconspider=False,
        hunter=False,
        websites_file=None,
        vulscan=False,
        vulners=False,
    )

    run_inventa(args)

    output = capsys.readouterr().out
    json_files = list(out_dir.glob("inventa_data_*.json"))

    assert len(json_files) == 1
    assert "No assets discovered" in output


def test_run_inventa_wires_passive_dns_and_cloud_enum(tmp_path, monkeypatch):
    scope_file = tmp_path / "scope.txt"
    targets_file = tmp_path / "targets.txt"
    websites_file = tmp_path / "websites.txt"
    out_dir = tmp_path / "results"

    scope_file.write_text("203.0.113.0/24\n10.0.0.0/8\n", encoding="utf-8")
    targets_file.write_text("example.com\n10.0.0.5\n", encoding="utf-8")
    websites_file.write_text("portal.example.com\n", encoding="utf-8")

    import modules.passive_dns
    import modules.cloud_enum

    monkeypatch.setattr(
        modules.passive_dns,
        "passive_dns_enum",
        lambda domain, scope_cidrs: [
            {
                "source": "passive_dns",
                "hostname": f"www.{domain}",
                "ip": "203.0.113.10",
                "ports": [],
                "services": [],
            }
        ],
    )
    monkeypatch.setattr(
        modules.cloud_enum,
        "cloud_enumerate",
        lambda provider="aws": [
            {
                "source": "aws_ec2",
                "cloud_provider": "aws",
                "resource_type": "ec2",
                "ip": "10.0.0.25",
                "ports": [],
                "services": [],
            }
        ],
    )

    args = argparse.Namespace(
        scope=str(scope_file),
        targets_file=str(targets_file),
        profile="low",
        out=str(out_dir),
        report="none",
        banner_grab=False,
        fingerprint=False,
        vuln_check=False,
        tls=False,
        topology=False,
        compliance=False,
        osint=False,
        passive_dns=True,
        cloud_enum=True,
        ai=False,
        history=False,
        no_active=True,
        cloud_scraper=False,
        web_inspect=False,
        subdomain_enum=False,
        smap=False,
        masscan=False,
        zmap=False,
        zgrab2=False,
        zgrab2_module="http",
        domain_recon=False,
        striker=False,
        reconspider=False,
        hunter=False,
        websites_file=str(websites_file),
        vulscan=False,
        vulners=False,
    )

    run_inventa(args)

    json_files = list(out_dir.glob("inventa_data_*.json"))
    assert len(json_files) == 1

    data = json.loads(json_files[0].read_text(encoding="utf-8"))
    sources = {asset["source"] for asset in data}
    assert "passive_dns" in sources
    assert "aws_ec2" in sources


def test_run_inventa_wires_domain_recon(tmp_path, monkeypatch):
    scope_file = tmp_path / "scope.txt"
    targets_file = tmp_path / "targets.txt"
    websites_file = tmp_path / "websites.txt"
    out_dir = tmp_path / "results"

    scope_file.write_text("203.0.113.0/24\n", encoding="utf-8")
    targets_file.write_text("203.0.113.10\n", encoding="utf-8")
    websites_file.write_text("example.com\n", encoding="utf-8")

    import modules.domain_recon

    monkeypatch.setattr(
        modules.domain_recon,
        "run_domain_recon",
        lambda domains, out: [
            {
                "source": "domain_recon",
                "hostname": "app.example.com",
                "ip": "203.0.113.10",
                "ports": [],
                "services": [],
            }
        ],
    )

    args = argparse.Namespace(
        scope=str(scope_file),
        targets_file=str(targets_file),
        profile="low",
        out=str(out_dir),
        report="none",
        banner_grab=False,
        fingerprint=False,
        vuln_check=False,
        tls=False,
        topology=False,
        compliance=False,
        osint=False,
        passive_dns=False,
        cloud_enum=False,
        ai=False,
        history=False,
        no_active=True,
        cloud_scraper=False,
        web_inspect=False,
        subdomain_enum=False,
        smap=False,
        masscan=False,
        zmap=False,
        zgrab2=False,
        zgrab2_module="http",
        domain_recon=True,
        striker=False,
        reconspider=False,
        hunter=False,
        websites_file=str(websites_file),
        vulscan=False,
        vulners=False,
    )

    run_inventa(args)

    data = json.loads(next(out_dir.glob("inventa_data_*.json")).read_text(encoding="utf-8"))
    assert any(asset["source"] == "domain_recon" for asset in data)


def test_run_inventa_allows_cloud_only_without_scope(tmp_path, monkeypatch):
    out_dir = tmp_path / "results"

    import modules.cloud_enum

    monkeypatch.setattr(
        modules.cloud_enum,
        "cloud_enumerate",
        lambda provider="aws": [
            {
                "source": "aws_ec2",
                "cloud_provider": "aws",
                "resource_type": "vm",
                "resource_id": "i-123",
                "name": "web-1",
                "ip": "10.0.0.5",
                "ports": [],
                "services": [],
            }
        ],
    )

    args = argparse.Namespace(
        scope=None,
        scope_cidr=[],
        targets_file=None,
        target=[],
        profile="low",
        out=str(out_dir),
        report="none",
        banner_grab=False,
        fingerprint=False,
        vuln_check=False,
        tls=False,
        topology=False,
        compliance=False,
        osint=False,
        passive_dns=False,
        cloud_enum=True,
        cloud_provider="aws",
        ai=False,
        history=False,
        no_active=True,
        cloud_scraper=False,
        web_inspect=False,
        subdomain_enum=False,
        smap=False,
        masscan=False,
        zmap=False,
        zgrab2=False,
        zgrab2_module="http",
        domain_recon=False,
        striker=False,
        reconspider=False,
        hunter=False,
        websites_file=None,
        website=[],
        exclude_file=None,
        vulscan=False,
        vulners=False,
    )

    run_inventa(args)

    data = json.loads(next(out_dir.glob("inventa_data_*.json")).read_text(encoding="utf-8"))
    assert data[0]["resource_id"] == "i-123"
