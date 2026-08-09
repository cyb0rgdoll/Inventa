from __future__ import annotations

from pathlib import Path

import requests

from modules import osint


class DummyResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class DummySession:
    def __init__(self, response: DummyResponse):
        self.response = response
        self.urls = []

    def get(self, url, timeout=None):
        self.urls.append(url)
        return self.response


class RequestFailingSession:
    def get(self, url, timeout=None):
        raise requests.exceptions.ConnectionError(
            f"failed for url: {url}?key=super-secret-token"
        )


def setup_function():
    osint._UNAVAILABLE_PROVIDERS.clear()


def test_load_provider_config_includes_builtwith(monkeypatch):
    monkeypatch.setenv("BUILTWITH_API_KEY", "bw-test-key")

    config = osint.load_provider_config()

    assert config["builtwith"] == "bw-test-key"


def test_query_builtwith_domain_normalizes_technology_data(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(osint, "CACHE_DIR", tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)

    payload = {
        "Results": [
            {
                "Result": {
                    "Paths": [
                        {
                            "Domain": "example.com",
                            "SubDomain": "www",
                            "Technologies": [
                                {
                                    "Name": "nginx",
                                    "Parent": "Web Server",
                                    "Tag": "hosting",
                                    "Categories": ["Reverse Proxy"],
                                },
                                {
                                    "Name": "React",
                                    "Tag": "javascript",
                                    "Categories": ["Framework"],
                                },
                            ],
                        }
                    ]
                },
                "Meta": {
                    "CompanyName": "Example Corp",
                    "Country": "AU",
                    "Vertical": "Technology",
                    "Social": ["https://linkedin.com/company/example"],
                },
                "LastIndexed": 1769472000000,
            }
        ]
    }
    session = DummySession(DummyResponse(payload))

    result = osint.query_builtwith_domain("example.com", "bw-key", session)

    assert result is not None
    assert result["provider"] == "builtwith"
    assert result["target"] == "example.com"
    assert result["organization"] == "Example Corp"
    assert result["country"] == "AU"
    assert result["hostnames"] == ["www.example.com"]
    assert result["technology_count"] == 2
    assert result["technologies"] == ["nginx", "React"]
    assert "hosting" in result["tags"]
    assert "Framework" in result["tags"]
    assert "Web Server" in result["services"]
    assert "React" in result["services"]
    assert session.urls


def test_query_ipinfo_ip_normalizes_basic_metadata(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(osint, "CACHE_DIR", tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)

    payload = {
        "ip": "8.8.8.8",
        "asn": "AS15169",
        "as_name": "Google LLC",
        "as_domain": "google.com",
        "country_code": "US",
        "country": "United States",
        "continent_code": "NA",
        "continent": "North America",
    }
    session = DummySession(DummyResponse(payload))

    result = osint.query_ipinfo_ip("8.8.8.8", "ipinfo-key", session)

    assert result is not None
    assert result["provider"] == "ipinfo"
    assert result["target"] == "8.8.8.8"
    assert result["organization"] == "Google LLC"
    assert result["asn"] == "AS15169"
    assert result["country"] == "US"
    assert result["as_domain"] == "google.com"
    assert result["continent"] == "NA"
    assert session.urls


def test_query_shodan_ip_unauthorized_disables_provider(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(osint, "CACHE_DIR", tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    session = DummySession(DummyResponse({}, status_code=401))

    result = osint.query_shodan_ip("3.27.42.239", "bad-key", session)

    assert result is None
    assert "shodan" in osint._UNAVAILABLE_PROVIDERS
    assert "invalid or unauthorized API key" in capsys.readouterr().out


def test_osint_request_errors_redact_query_secrets(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(osint, "CACHE_DIR", tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)

    result = osint.query_shodan_ip("3.27.42.239", "super-secret-token", RequestFailingSession())

    output = capsys.readouterr().out
    assert result is None
    assert "super-secret-token" not in output
    assert "key=<redacted>" in output


def test_skip_providers_env_disables_configured_providers(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-key")
    monkeypatch.setenv("CENSYS_API_ID", "censys-id")
    monkeypatch.setenv("CENSYS_API_SECRET", "censys-secret")
    monkeypatch.setenv("INVENTA_OSINT_SKIP_PROVIDERS", "shodan,censys,bgpview")

    config = osint.load_provider_config()

    assert config["shodan"] is None
    assert config["censys_id"] is None
    assert config["censys_secret"] is None
    assert config["bgpview"] is None
