import ipaddress
import socket

import pytest

from modules.scope import load_scope, validate_discovered_ip, validate_target


def test_load_scope_skips_comments_and_invalid_rows(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        "# comment\n"
        "192.168.1.10/24\n"
        "invalid-entry\n"
        "10.0.0.0/8\n",
        encoding="utf-8",
    )

    cidrs = load_scope(str(scope_file))

    assert cidrs == [
        ipaddress.IPv4Network("192.168.1.0/24"),
        ipaddress.IPv4Network("10.0.0.0/8"),
    ]


def test_validate_target_accepts_in_scope_ip():
    scope = [ipaddress.IPv4Network("192.168.1.0/24")]
    assert validate_target("192.168.1.20", scope) is True
    assert validate_target("192.168.2.20", scope) is False


def test_validate_target_resolves_hostname(monkeypatch):
    scope = [ipaddress.IPv4Network("203.0.113.0/24")]

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0))
        ],
    )

    assert validate_target("example.test", scope) is True


def test_validate_discovered_ip_rejects_invalid_input():
    scope = [ipaddress.IPv4Network("192.168.1.0/24")]
    assert validate_discovered_ip("not-an-ip", scope) is False


def test_load_scope_raises_when_no_valid_ranges(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("# comment only\n", encoding="utf-8")

    with pytest.raises(ValueError, match="No valid CIDR ranges found"):
        load_scope(str(scope_file))
