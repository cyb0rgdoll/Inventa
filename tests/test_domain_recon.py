from pathlib import Path

from modules.domain_recon import _merge_recon_results, _normalize_domains


def test_normalize_domains_filters_to_parent_domain():
    values = ["api.example.com", "EXAMPLE.com", "other.test", " bad "]

    result = _normalize_domains(values, "example.com")

    assert result == {"api.example.com", "example.com"}


def test_merge_recon_results_combines_httpx_nuclei_and_nmap():
    live_hosts = [
        {"url": "https://api.example.com", "host": "api.example.com", "port": 443, "scheme": "https"},
    ]
    tech_by_url = {"https://api.example.com": ["nginx", "next.js"]}
    nuclei_by_url = {
        "https://api.example.com": [
            {"template_id": "exposed-panel", "severity": "medium", "info": {}},
        ]
    }
    nmap_assets = [
        {
            "source": "nmap",
            "hostname": "api.example.com",
            "ip": "203.0.113.10",
            "ports": [{"port": "443", "protocol": "tcp", "service": "https", "version": "nginx"}],
            "services": ["https"],
            "vulnerabilities": [],
        }
    ]

    assets = _merge_recon_results("example.com", live_hosts, tech_by_url, nuclei_by_url, nmap_assets)

    assert len(assets) == 1
    asset = assets[0]
    assert asset["source"] == "domain_recon"
    assert asset["hostname"] == "api.example.com"
    assert asset["ip"] == "203.0.113.10"
    assert "https://api.example.com" in asset["domain_recon"]["urls"]
    assert asset["domain_recon"]["technologies"]["https://api.example.com"] == ["nginx", "next.js"]
    assert asset["domain_recon"]["nuclei_findings"]["https://api.example.com"][0]["template_id"] == "exposed-panel"
    assert any(v["source"] == "nuclei" for v in asset["vulnerabilities"])
