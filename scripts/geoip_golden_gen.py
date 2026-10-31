#!/usr/bin/env python3
"""Generate deterministic cross-language golden vectors for the covering merge.

Rust (`src/server/geoip_panel/covering.rs::golden_vectors_match_python_expectations`)
and Python (`scripts/geoip_golden_test.py`) read the **same**
`geoip_golden_vectors.json`; each case's `expected` is computed here by an
independent reference implementation of the documented score:

    score = (saturating_i64(weight + bits * gain), epoch, bits)
    equal score -> later row wins; empty never overwrites non-empty
    special country codes (ZZ/XX/A1/A2) and CN+foreign-city pollution ignored

The generator also cross-checks every expected value against
`geoip_common.merge_covering` before writing, so a divergence between the
reference formula and the shipped Python merge fails here instead of silently
blessing wrong vectors.

Usage: python3 scripts/geoip_golden_gen.py [--out PATH] [--count N]
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import (  # noqa: E402
    DEFAULT_PATH_PRIORITY_GAIN,
    cn_city_polluted,
    country_vote_ok,
    merge_covering,
)

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
# Rust hardcodes epoch=0 for these (no e_region/e_dc/e_division_code column in the
# query path), so vectors must not rely on their field epoch.
NO_FIELD_EPOCH = {"region", "dc", "division_code"}
GAINS = (0, 10, 50)
I64_MAX = (1 << 63) - 1
I64_MIN = -(1 << 63)


def sat(v: int) -> int:
    return max(I64_MIN, min(I64_MAX, v))


def score(weight: int, bits: int, epoch: int, gain: int) -> tuple[int, int, int]:
    return (sat(weight + sat(bits * gain)), epoch, bits)


def reference_merge(rows: list[dict], gain: int) -> dict[str, str]:
    out: dict[str, str] = {}
    for field in FIELDS:
        best_val = ""
        best_score: tuple[int, int, int] | None = None
        for row in rows:
            val = str(row.get(field, "") or "")
            if field == "country" and not country_vote_ok(val):
                val = ""
            if field == "city" and cn_city_polluted(str(row.get("country", "") or ""), val):
                val = ""
            if not val:
                continue
            epoch = 0 if field in NO_FIELD_EPOCH else int(row.get(f"e_{field}", 0) or 0)
            if epoch <= 0:
                epoch = int(row.get("commit_unix", 0) or 0)
            s = score(int(row.get("weight", 0) or 0), int(row.get("bits", 0) or 0), epoch, gain)
            if best_score is None or s >= best_score:
                best_val = val
                best_score = s
        out[field] = best_val
    return out


def check_against_common(rows: list[dict], gain: int, expected: dict[str, str]) -> None:
    prepared = []
    for r in rows:
        row = dict(r)
        row.setdefault("prefix", "")
        row.setdefault("weight", 0)
        row.setdefault("bits", 0)
        row.setdefault("commit_unix", 0)
        row.setdefault("ip_start", "")
        row.setdefault("ip_end", "")
        prepared.append(row)
    got = merge_covering(prepared, path_priority_gain=gain)
    for field in FIELDS:
        if getattr(got, field) != expected.get(field, ""):
            raise SystemExit(
                f"reference/merge divergence field={field} gain={gain}: "
                f"{getattr(got, field)!r} != {expected.get(field, '')!r}\nrows={rows}"
            )


COUNTRY_POOL = ["US", "CN", "DE", "JP", "GB", "SG", "ZZ", "XX", "A1", "A2", "CN", "US"]
PROVINCE_POOL = ["California", "浙江省", "Bavaria", "Tokyo", "London", ""]
CITY_POOL = [
    "San Jose", "杭州", "Munich", "Tokyo", "London", "美国洛杉矶", "上海", "",
]
ISP_POOL = ["Comcast", "中国电信", "Deutsche Telekom", "NTT", "BT", ""]
ASN_POOL = ["7922", "4134", "3320", "2914", "2856", ""]
ORG_POOL = ["COMCAST", "CHINANET", "DTAG", "NTT", "BT", ""]
CLOUD_POOL = ["AWS", "Tencent Cloud", "Google", "Aliyun", ""]
CLOUD_REGION_POOL = ["us-west-1", "us-sanjose-1", "europe-west1", "cn-hangzhou", ""]
CLOUD_SVC_POOL = ["ec2", "cvm", "gce", "ecs", ""]
HOSTING_POOL = ["IDC", "ipapi-hosting", ""]
WEIGHT_POOL = [0, 10, 40, 50, 80, 100, 150, 200, 250, 300, 400, 700, 820, 900, 990]
BITS_POOL = [0, 8, 12, 16, 20, 24, 28, 32, 48, 56, 64, 112, 128]
EPOCH_POOL = [0, 0, 0, 1, 5, 10, 100, 500, 2000]
COMMIT_POOL = [0, 1, 5, 10, 100, 500, 2000]


def make_case(rng: random.Random, idx: int, gain: int) -> dict:
    nrows = rng.choice([2, 2, 3, 3, 4, 5])
    rows = []
    # Guarantee at least two rows share the same (weight,bits,commit) sometimes,
    # to exercise "later row wins" ties.
    tie_mode = rng.randrange(4) == 0
    tie_bits = rng.choice(BITS_POOL)
    tie_weight = rng.choice(WEIGHT_POOL)
    tie_commit = rng.choice(COMMIT_POOL)
    for _ in range(nrows):
        if tie_mode and len(rows) >= 2:
            weight, bits, commit = tie_weight, tie_bits, tie_commit
        else:
            weight = rng.choice(WEIGHT_POOL)
            bits = rng.choice(BITS_POOL)
            commit = rng.choice(COMMIT_POOL)
        row = {
            "weight": weight,
            "bits": bits,
            "commit_unix": commit,
            "country": rng.choice(COUNTRY_POOL),
            "province": rng.choice(PROVINCE_POOL),
            "region": rng.choice(["CA", "ZJ", "BY", "13", "ENG", ""]),
            "city": rng.choice(CITY_POOL),
            "district": rng.choice(["西湖区", "Chiyoda", "SoMa", ""]),
            "isp": rng.choice(ISP_POOL),
            "dc": rng.choice(["LAX1", "HGH1", "FRA2", ""]),
            "asn": rng.choice(ASN_POOL),
            "as_org": rng.choice(ORG_POOL),
            "net_org": rng.choice(["CHINANET-ZJ", "COMCAST-IP", "DTAG-NET", ""]),
            "cloud_provider": rng.choice(CLOUD_POOL),
            "cloud_region": rng.choice(CLOUD_REGION_POOL),
            "cloud_service": rng.choice(CLOUD_SVC_POOL),
            "hosting": rng.choice(HOSTING_POOL),
            "division_code": rng.choice(["330106", "13101", "94107", ""]),
        }
        # Field epochs only for fields the Rust query path actually forwards.
        for field in ("country", "province", "city", "district", "isp", "asn",
                      "as_org", "net_org", "cloud_provider", "cloud_region",
                      "cloud_service", "hosting"):
            e = rng.choice(EPOCH_POOL)
            if e:
                row[f"e_{field}"] = e
        rows.append(row)
    # Occasionally force the classic gain-sensitive shape: heavy wide prefix vs
    # zero-weight long prefix; the three gain levels then disagree.
    if idx % 9 == 0:
        rows = [
            {"country": "AA", "weight": 700, "bits": 8, "commit_unix": 5},
            {"country": "BB", "weight": 0, "bits": 24, "commit_unix": 5},
        ]
    elif idx % 9 == 1:
        rows = [
            {"country": "AA", "weight": 250, "bits": 8, "commit_unix": 5},
            {"country": "BB", "weight": 100, "bits": 24, "commit_unix": 5},
        ]
    elif idx % 9 == 2:
        rows = [
            {"country": "AA", "weight": I64_MAX, "bits": 0, "commit_unix": 99},
            {"country": "BB", "weight": I64_MAX, "bits": 8, "commit_unix": 1},
        ]
    expected = reference_merge(rows, gain)
    check_against_common(rows, gain, expected)
    return {
        "name": f"gen_{idx:03d}_gain{gain}",
        "gain": gain,
        "rows": rows,
        "expected": {k: v for k, v in expected.items() if v},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out",
        default=str(Path(__file__).with_name("geoip_golden_vectors.json")),
    )
    ap.add_argument("--count", type=int, default=36, help="generated base cases")
    args = ap.parse_args()
    out_path = Path(args.out)
    existing = json.loads(out_path.read_text(encoding="utf-8")) if out_path.is_file() else {}
    hand = [c for c in existing.get("cases", []) if not str(c.get("name", "")).startswith("gen_")]
    rng = random.Random(20261030)
    gen = []
    for i in range(args.count):
        for gain in GAINS:
            gen.append(make_case(rng, i, gain))
    doc = {
        "comment": (
            "G-10 golden vectors: Rust src/server/geoip_panel/covering.rs and "
            "Python scripts/geoip_common.py must produce identical merged fields "
            "for these inputs. Score = (weight + bits * path_priority_gain, epoch, "
            "bits); equal scores -> later row wins; empty never overwrites "
            "non-empty. gen_* cases are reproducible via scripts/geoip_golden_gen.py "
            "and cover gains 0/10/50."
        ),
        "path_priority_gain": int(
            existing.get("path_priority_gain", DEFAULT_PATH_PRIORITY_GAIN)
        ),
        "cases": hand + gen,
    }
    out_path.write_text(
        json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"geoip_golden_gen: wrote {len(hand)} hand-written + {len(gen)} generated "
        f"cases to {out_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
