#!/usr/bin/env python3
"""G-10 cross-language golden vectors for the GeoIP covering merge.

Rust `src/server/geoip_panel/covering.rs::golden_vectors_match_python_expectations`
reads the same `scripts/geoip_golden_vectors.json` and asserts the identical
expected fields.  Any divergence between the offline Python merge and the
runtime Rust merge fails on at least one side.

Usage: python3 scripts/geoip_golden_test.py [--vectors PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from geoip_common import DEFAULT_PATH_PRIORITY_GAIN, merge_covering

FIELDS = (
    "country",
    "province",
    "region",
    "city",
    "district",
    "isp",
    "dc",
    "asn",
    "as_org",
    "net_org",
    "cloud_provider",
    "cloud_region",
    "cloud_service",
    "hosting",
    "division_code",
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--vectors",
        default=str(Path(__file__).with_name("geoip_golden_vectors.json")),
    )
    args = ap.parse_args()
    data = json.loads(Path(args.vectors).read_text(encoding="utf-8"))
    default_gain = int(data.get("path_priority_gain", DEFAULT_PATH_PRIORITY_GAIN))
    failures = 0
    for case in data["cases"]:
        gain = int(case.get("gain", default_gain))
        rows = []
        for r in case["rows"]:
            row = dict(r)
            row.setdefault("prefix", "")
            row.setdefault("weight", 0)
            row.setdefault("bits", 0)
            row.setdefault("commit_unix", 0)
            row.setdefault("ip_start", "")
            row.setdefault("ip_end", "")
            rows.append(row)
        merged = merge_covering(rows, path_priority_gain=gain)
        expected = case.get("expected", {})
        for field in FIELDS:
            want = expected.get(field, "")
            got = getattr(merged, field)
            if got != want:
                failures += 1
                print(
                    f"FAIL {case['name']} (gain={gain}) {field}: "
                    f"got {got!r} want {want!r}",
                    file=sys.stderr,
                )
    total = len(data["cases"])
    if failures:
        print(f"{failures} mismatch(es) across {total} golden cases", file=sys.stderr)
        return 1
    print(f"OK: {total} golden cases, all fields match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
