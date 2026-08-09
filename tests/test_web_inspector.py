from pathlib import Path

from modules import web_inspector


def test_parse_nikto_output_extracts_findings(tmp_path: Path):
    output = tmp_path / "nikto.json"
    output.write_text(
        """
{
  "vulnerabilities": [
    {
      "id": "999001",
      "msg": "Server leaks inode information",
      "uri": "/icons/README",
      "references": ["https://example.com/ref1"]
    },
    {
      "msgid": "999002",
      "description": "Missing X-Frame-Options header",
      "url": "/",
      "ref": ["https://example.com/ref2"]
    }
  ]
}
""".strip(),
        encoding="utf-8",
    )

    result = web_inspector._parse_nikto_output(output)

    assert result["status"] == "ok"
    assert result["finding_count"] == 2
    assert result["findings"][0]["id"] == "999001"
    assert result["findings"][0]["uri"] == "/icons/README"
    assert result["findings"][1]["id"] == "999002"
    assert result["findings"][1]["message"] == "Missing X-Frame-Options header"
