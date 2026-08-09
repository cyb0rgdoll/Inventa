import json

from modules.cloud_enum_external import _finding_to_asset, _parse_cloud_enum_log


def test_cloud_enum_finding_to_asset_normalizes_azure_vm_dns():
    asset = _finding_to_asset({
        "platform": "azure",
        "msg": "Registered Azure Virtual Machine DNS Name",
        "target": "lab.australiaeast.cloudapp.azure.com",
        "access": "public",
    })

    assert asset["source"] == "cloud_enum"
    assert asset["cloud_provider"] == "azure"
    assert asset["resource_type"] == "vm_dns"
    assert asset["hostname"] == "lab.australiaeast.cloudapp.azure.com"
    assert asset["externally_exposed"] is True


def test_parse_cloud_enum_jsonl_skips_headers(tmp_path):
    log = tmp_path / "cloud_enum.jsonl"
    log.write_text(
        "#### CLOUD_ENUM header ####\n"
        + json.dumps({
            "platform": "aws",
            "msg": "OPEN S3 BUCKET",
            "target": "https://example.s3.amazonaws.com",
            "access": "public",
        })
        + "\n",
        encoding="utf-8",
    )

    assets = _parse_cloud_enum_log(log)

    assert len(assets) == 1
    assert assets[0]["cloud_provider"] == "aws"
    assert assets[0]["resource_type"] == "storage"
