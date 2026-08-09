from pathlib import Path

from modules import smap_scan


def test_run_smap_missing_binary_returns_empty(monkeypatch, tmp_path: Path, capsys):
    monkeypatch.setattr(smap_scan, "_find_binary", lambda: None)

    assets = smap_scan.run_smap(["203.0.113.10"], tmp_path)

    output = capsys.readouterr().out
    assert assets == []
    assert "smap binary not found" in output


def test_run_smap_creates_output_directory(monkeypatch, tmp_path: Path):
    class Result:
        returncode = 0
        stderr = ""
        stdout = ""

    monkeypatch.setattr(smap_scan, "_find_binary", lambda: "smap")
    monkeypatch.setattr(smap_scan.subprocess, "run", lambda *args, **kwargs: Result())

    out_dir = tmp_path / "nested" / "results"
    assets = smap_scan.run_smap(["203.0.113.10"], out_dir)

    assert assets == []
    assert out_dir.exists()
