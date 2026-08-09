from pathlib import Path

from modules.striker_scan import _dataset_to_assets, _extract_json_dataset


def test_extract_json_dataset_reads_trailing_json():
    output = "banner line\n{\"app.example.com\":{\"ip\":\"203.0.113.10\",\"ports\":[80,443],\"schema\":\"https\",\"cms\":\"wordpress\",\"forms\":[],\"all_urls\":[\"https://app.example.com\"],\"technologies\":[\"nginx\"],\"outdated_libs\":[]}}\n"

    parsed = _extract_json_dataset(output)

    assert parsed["app.example.com"]["ip"] == "203.0.113.10"


def test_dataset_to_assets_maps_striker_fields(tmp_path: Path):
    raw_file = tmp_path / "striker.txt"
    raw_file.write_text("raw", encoding="utf-8")
    dataset = {
        "app.example.com": {
            "ip": "203.0.113.10",
            "ports": [80, 443],
            "schema": "https",
            "cms": "wordpress",
            "forms": [],
            "all_urls": ["https://app.example.com"],
            "technologies": ["nginx"],
            "outdated_libs": [],
        }
    }

    assets = _dataset_to_assets("example.com", dataset, raw_file)

    assert len(assets) == 1
    asset = assets[0]
    assert asset["source"] == "striker"
    assert asset["hostname"] == "app.example.com"
    assert asset["ip"] == "203.0.113.10"
    assert asset["endpoint"] == "https://app.example.com"
    assert "wordpress" in asset["services"]
