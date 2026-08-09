from pathlib import Path

from modules.reporter import generate_csv_report, generate_html_report


def test_generate_html_report_accepts_integer_ports(tmp_path: Path):
    output_path = tmp_path / "report.html"

    generate_html_report(
        [
            {
                "ip": "1.2.3.4",
                "ports": [{"port": 443, "protocol": "tcp"}],
                "services": ["https"],
            }
        ],
        output_path,
    )

    html = output_path.read_text(encoding="utf-8")
    assert "1.2.3.4" in html
    assert "443" in html


def test_generate_csv_report_accepts_integer_ports(tmp_path: Path):
    output_path = tmp_path / "report.csv"

    generate_csv_report(
        [
            {
                "ip": "1.2.3.4",
                "ports": [{"port": 443, "protocol": "tcp"}],
                "services": ["https"],
            }
        ],
        output_path,
    )

    csv_text = output_path.read_text(encoding="utf-8")
    assert "1.2.3.4" in csv_text
    assert "443" in csv_text

def test_html_report_escapes_asset_fields(tmp_path: Path):
    output_path = tmp_path / "report.html"
    bad_script = chr(60) + "script" + chr(62) + "alert(1)" + chr(60) + "/script" + chr(62)
    bad_image = chr(60) + "img src=x onerror=alert(1)" + chr(62)
    generate_html_report(
        [
            {
                "ip": "192.0.2.10",
                "hostname": bad_script,
                "asset_type": "server",
                "services": ["http", bad_image],
            }
        ],
        output_path,
    )
    html = output_path.read_text(encoding="utf-8")
    assert bad_script not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert bad_image not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
