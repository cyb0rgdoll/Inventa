#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path


def asset_key(asset: dict) -> str | None:
    return asset.get("public_ip") or asset.get("ip") or asset.get("hostname") or asset.get("resource_id") or asset.get("name")


def latest_json(run_dir: Path) -> Path | None:
    files = sorted(run_dir.glob("inventa_data_*.json"))
    return files[-1] if files else None


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: summarise_experiment.py OUT_ROOT BASELINE_CSV", file=sys.stderr)
        return 2

    out_root = Path(sys.argv[1])
    baseline_csv = Path(sys.argv[2])
    baseline_rows = list(csv.DictReader(baseline_csv.open(newline="", encoding="utf-8")))
    expected_ips = {row["ip"] for row in baseline_rows if row.get("ip")}

    summary_rows = []
    discovered_by_config: dict[str, list[set[str]]] = {}

    for run_dir in sorted(out_root.glob("*/run_*")):
        data_file = latest_json(run_dir)
        if data_file is None:
            continue
        assets = json.loads(data_file.read_text(encoding="utf-8"))
        discovered = {key for asset in assets if (key := asset_key(asset))}
        discovered_ips = {value for value in discovered if value.count(".") == 3}
        matched = discovered_ips & expected_ips
        config = run_dir.parent.name
        discovered_by_config.setdefault(config, []).append(discovered_ips)
        summary_rows.append(
            {
                "configuration": config,
                "run": run_dir.name,
                "assets_discovered": len(assets),
                "unique_asset_keys": len(discovered),
                "baseline_ip_matches": len(matched),
                "baseline_ip_total": len(expected_ips),
                "baseline_ip_recall": f"{(len(matched) / len(expected_ips)):.3f}" if expected_ips else "0.000",
                "json_file": str(data_file.relative_to(out_root)),
            }
        )

    for config, runs in discovered_by_config.items():
        if len(runs) < 2:
            continue
        stable = set.intersection(*runs) if runs else set()
        union = set.union(*runs) if runs else set()
        summary_rows.append(
            {
                "configuration": config,
                "run": "repeatability",
                "assets_discovered": "",
                "unique_asset_keys": "",
                "baseline_ip_matches": "",
                "baseline_ip_total": len(expected_ips),
                "baseline_ip_recall": "",
                "json_file": f"stable_ip_count={len(stable)}; union_ip_count={len(union)}; stability={len(stable) / len(union):.3f}" if union else "stable_ip_count=0; union_ip_count=0; stability=0.000",
            }
        )

    output = out_root / "evaluation_summary.csv"
    with output.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "configuration",
            "run",
            "assets_discovered",
            "unique_asset_keys",
            "baseline_ip_matches",
            "baseline_ip_total",
            "baseline_ip_recall",
            "json_file",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_rows)

    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
