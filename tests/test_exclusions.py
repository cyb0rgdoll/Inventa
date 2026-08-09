from modules.exclusions import ExclusionRules


def test_exclusions_filter_ips_cidrs_domains_and_keywords():
    rules = ExclusionRules([
        "192.0.2.10",
        "10.0.0.0/24",
        "*.internal.example.com",
        "*cdn*",
    ])

    assert rules.is_excluded("192.0.2.10") is True
    assert rules.is_excluded("10.0.0.55") is True
    assert rules.is_excluded("10.0.0.0/25") is True
    assert rules.is_excluded("api.internal.example.com") is True
    assert rules.is_excluded("static-cdn.example.com") is True
    assert rules.is_excluded("app.example.com") is False


def test_exclusions_filter_assets_by_cloud_resource_fields():
    rules = ExclusionRules(["*.internal.example.com", "198.51.100.20"])
    assets = [
        {"name": "api.internal.example.com", "ports": [], "services": []},
        {"public_ip": "198.51.100.20", "ports": [], "services": []},
        {"name": "public-app", "public_ip": "198.51.100.21", "ports": [], "services": []},
    ]

    filtered = rules.filter_assets(assets)

    assert filtered == [assets[2]]
