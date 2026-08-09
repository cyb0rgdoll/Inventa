import json

from modules.vhostscan import _parse_vhostscan_json


def test_parse_vhostscan_json_normalizes_virtual_hosts(tmp_path):
    output = tmp_path / "vhostscan.json"
    output.write_text(json.dumps({
        "Target": "20.70.194.22",
        "Port": 3000,
        "SSL": False,
        "Result": {
            "admin.example.test": {
                "Code": 200,
                "Hash": "abc123",
                "Headers": {"Server": "nginx"},
            }
        },
    }), encoding="utf-8")

    assets = _parse_vhostscan_json(output)

    assert len(assets) == 1
    assert assets[0]["source"] == "vhostscan"
    assert assets[0]["hostname"] == "admin.example.test"
    assert assets[0]["ip"] == "20.70.194.22"
    assert assets[0]["ports"][0]["port"] == "3000"
    assert assets[0]["vhostscan"]["status_code"] == 200
