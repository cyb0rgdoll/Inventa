from pathlib import Path

from modules import zmap_scan


def test_run_zmap_missing_binary_returns_empty(monkeypatch, tmp_path: Path, capsys):
    monkeypatch.setattr(zmap_scan, "_find_binary", lambda: None)

    assets = zmap_scan.run_zmap(["192.0.2.1"], "low", tmp_path)

    output = capsys.readouterr().out
    assert assets == []
    assert "zmap binary not found" in output


def test_root_prefix_uses_noninteractive_sudo(monkeypatch):
    monkeypatch.setattr(zmap_scan.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(zmap_scan.shutil, "which", lambda name: "/usr/bin/sudo" if name == "sudo" else None)

    prefix = zmap_scan._root_prefix("zmap")

    assert prefix == ["sudo", "-n", "zmap"]
