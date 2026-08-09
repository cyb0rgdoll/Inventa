from pathlib import Path

from modules.reconspider_scan import _attach_reconspider_output


def test_attach_reconspider_output_updates_matching_asset(tmp_path: Path):
    assets = [
        {
            "source": "domain_recon",
            "hostname": "api.example.com",
            "fqdn": "api.example.com",
            "domain": "example.com",
            "ports": [],
            "services": [],
        }
    ]
    raw = tmp_path / "reconspider.txt"
    raw.write_text("raw", encoding="utf-8")

    _attach_reconspider_output(assets, "example.com", raw)

    assert assets[0]["external_recon"]["reconspider"]["status"] == "completed"


def test_attach_reconspider_output_creates_placeholder_asset(tmp_path: Path):
    assets = []
    raw = tmp_path / "reconspider.txt"
    raw.write_text("raw", encoding="utf-8")

    _attach_reconspider_output(assets, "example.com", raw)

    assert len(assets) == 1
    assert assets[0]["source"] == "reconspider"
