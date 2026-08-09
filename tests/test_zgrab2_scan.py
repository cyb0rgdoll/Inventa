from pathlib import Path

from modules.zgrab2_scan import _parse_zgrab2_jsonl


def test_parse_zgrab2_jsonl_extracts_http_asset(tmp_path: Path):
    output = tmp_path / "zgrab2.jsonl"
    output.write_text(
        '{"ip":"93.184.216.34","domain":"example.com","data":{"http":{"status":"success","protocol":"http","port":443,"result":{"response":{"status_code":200}}}}}\n',
        encoding="utf-8",
    )

    assets = _parse_zgrab2_jsonl(output, "http")

    assert assets == [
        {
            "source": "zgrab2",
            "ip": "93.184.216.34",
            "hostname": "example.com",
            "endpoint": "example.com",
            "ports": [
                {
                    "port": "443",
                    "protocol": "tcp",
                    "service": "http",
                    "version": None,
                }
            ],
            "services": ["http"],
            "zgrab2": {
                "http": {
                    "status": "success",
                    "protocol": "http",
                    "port": 443,
                    "result": {"response": {"status_code": 200}},
                }
            },
        }
    ]
