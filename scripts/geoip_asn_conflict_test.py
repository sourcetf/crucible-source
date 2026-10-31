#!/usr/bin/env python3
"""Deterministic ASN/BGP multi-source conflict regression (U-09).

Covers:
  * same prefix, three sources, different ASN → BGP origin (weight 850) wins,
    conflict recorded once with sorted ASN list;
  * same-source MOAS → conflict, deterministic winner across re-runs;
  * BGP more-specific prefix beats a wider prefix at equal weight (bits*gain);
  * IPv4/IPv6 dual stack (v6 written to the `ipv6` range table and visible to
    `geoip_common.load_covering`, same rows Rust `load_from_range_table` reads);
  * anycast table UPSERT works (unique index on (start,end)) and is idempotent;
  * partial-source refresh keeps the other sources' existing rows;
  * CLI `--fixture` full flow, run twice → same rows/conflicts (idempotent).

Usage: python3 scripts/geoip_asn_conflict_test.py
"""
from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import (  # noqa: E402
    init_panel_schema,
    init_schema,
    load_covering,
    merge_covering,
    upsert_anycast,
)
from geoip_resolve_asn_bgp import SOURCES, ingest  # noqa: E402

FAILS = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global FAILS
    if cond:
        print(f"PASS {name}")
    else:
        FAILS += 1
        print(f"FAIL {name} {detail}")


def fresh() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    init_schema(conn)
    init_panel_schema(conn)
    return conn


def rec(source: str, start: str, end: str, asn: str, org: str = ""):
    return (source, start, end, asn, org, SOURCES[source]["weight"])


def merged(conn: sqlite3.Connection, ip: str):
    rows = load_covering(conn, ip)
    return merge_covering(rows), len(rows)


def conflicts(conn: sqlite3.Connection):
    return [
        (r[0], r[1])
        for r in conn.execute(
            "SELECT prefix, sources FROM panel_conflicts WHERE field='asn' ORDER BY prefix"
        )
    ]


def case_cross_source() -> None:
    base = "203.0.113.0"
    end = "203.0.113.255"
    records = [
        rec("asn-geolite2", base, end, "64502", "GEO"),
        rec("asn-bgp", base, end, "64500", "BGP"),
        rec("asn-iptoasn", base, end, "64501", "IPTOASN"),
    ]
    conn = fresh()
    stats = ingest(conn, records, replace_sources=tuple(SOURCES))
    m, _ = merged(conn, "203.0.113.9")
    check("cross_source_bgp_wins", m.asn == "64500", f"asn={m.asn}")
    check("cross_source_as_org", m.as_org == "BGP", f"org={m.as_org}")
    check("cross_source_conflict_count", stats["conflicts"] == 1, stats)
    got = conflicts(conn)
    check(
        "cross_source_conflict_sorted",
        got == [("203.0.113.0-203.0.113.255", "64500|64501|64502")],
        got,
    )
    # Re-run in a different insertion order: unchanged result and no duplicate conflict.
    conn2 = fresh()
    ingest(conn2, list(reversed(records)), replace_sources=tuple(SOURCES))
    m2, _ = merged(conn2, "203.0.113.9")
    check("cross_source_order_independent", m2.asn == "64500", f"asn={m2.asn}")
    ingest(conn2, list(reversed(records)), replace_sources=tuple(SOURCES))
    check("cross_source_rerun_idempotent", len(conflicts(conn2)) == 1, conflicts(conn2))


def case_moas() -> None:
    base, end = "198.51.100.0", "198.51.100.255"
    conn = fresh()
    ingest(
        conn,
        [rec("asn-bgp", base, end, "64510"), rec("asn-bgp", base, end, "64511")],
        replace_sources=("asn-bgp",),
    )
    (prefix, sig), = conflicts(conn)
    check("moas_conflict", prefix == f"{base}-{end}" and sig == "64510|64511", (prefix, sig))
    first, _ = merged(conn, "198.51.100.7")
    # 完全同分（同 source/weight/bits/commit）→ 行序确定：ingest 按 ASN 升序写入，
    # 合并侧同分后行胜 ⇒ 较大的 ASN 胜。重复 20 次必须一致。
    for _ in range(20):
        again, _ = merged(conn, "198.51.100.7")
        check_once = again.asn == first.asn
        if not check_once:
            check("moas_deterministic", False, f"{again.asn} != {first.asn}")
            return
    check("moas_deterministic", first.asn == "64511", f"asn={first.asn}")


def case_more_specific() -> None:
    conn = fresh()
    ingest(
        conn,
        [
            rec("asn-bgp", "203.0.0.0", "203.255.255.255", "64600", "WIDE"),
            rec("asn-bgp", "203.0.113.0", "203.0.113.255", "64601", "SPECIFIC"),
        ],
        replace_sources=("asn-bgp",),
    )
    m_specific, _ = merged(conn, "203.0.113.5")
    m_wide, _ = merged(conn, "203.1.2.3")
    check("bgp_more_specific_wins", m_specific.asn == "64601", f"asn={m_specific.asn}")
    check("bgp_wider_still_serves_outside", m_wide.asn == "64600", f"asn={m_wide.asn}")
    check("no_false_exact_conflict", conflicts(conn) == [], conflicts(conn))


def case_ipv6() -> None:
    conn = fresh()
    v6_base, v6_end = "2001:db8::", "2001:db8::ffff"
    records = [
        rec("asn-geolite2", v6_base, v6_end, "64702"),
        rec("asn-bgp", v6_base, v6_end, "64700"),
        rec("asn-iptoasn", v6_base, v6_end, "64701"),
        rec("asn-bgp", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "64699"),
        rec("asn-bgp", "2001:db8:1::", "2001:db8:1::ffff", "64799"),
    ]
    stats = ingest(conn, records, replace_sources=tuple(SOURCES))
    m, nrows = merged(conn, "2001:db8::5")
    check("ipv6_bgp_wins", m.asn == "64700", f"asn={m.asn} rows={nrows}")
    m2, _ = merged(conn, "2001:db8:1::5")
    check("ipv6_more_specific_wins", m2.asn == "64799", f"asn={m2.asn}")
    # v6 rows must live in ipv6 range table (what Rust load_from_range_table reads),
    # not the v4 geoip main table.
    n_v6 = conn.execute("SELECT COUNT(*) FROM ipv6").fetchone()[0]
    n_v6_main = conn.execute(
        "SELECT COUNT(*) FROM geoip WHERE ip_start LIKE '%:%'"
    ).fetchone()[0]
    check("ipv6_in_ipv6_table", n_v6 == 5, n_v6)
    check("ipv6_not_in_v4_main_table", n_v6_main == 0, n_v6_main)
    check("ipv6_conflicts", stats["conflicts"] == 1, stats)
    # start_i/end_i must be populated and match range_numeric_key.
    nulls = conn.execute(
        "SELECT COUNT(*) FROM ipv6 WHERE start_i IS NULL OR end_i IS NULL"
    ).fetchone()[0]
    check("ipv6_numeric_keys", nulls == 0, nulls)


def case_anycast() -> None:
    conn = fresh()
    upsert_anycast(conn, "198.51.100.0", "198.51.100.255", source="test-anycast")
    upsert_anycast(conn, "198.51.100.0", "198.51.100.255", source="test-anycast-2")
    n = conn.execute("SELECT COUNT(*) FROM anycast").fetchone()[0]
    row = conn.execute(
        "SELECT source, start_i, end_i FROM anycast WHERE start='198.51.100.0'"
    ).fetchone()
    check("anycast_upsert_unique", n == 1, n)
    check("anycast_last_write_wins", row[0] == "test-anycast-2", row)
    check("anycast_numeric_keys", row[1] is not None and row[2] is not None, row)
    conn2 = fresh()
    upsert_anycast(conn2, "2001:db8::", "2001:db8::ffff", source="v6-anycast")
    row6 = conn2.execute("SELECT source, start_i, end_i FROM anycast").fetchone()
    check("anycast_v6", row6[0] == "v6-anycast" and row6[1] is not None, row6)


def case_partial_refresh() -> None:
    conn = fresh()
    base, end = "192.0.2.0", "192.0.2.255"
    ingest(conn, [rec("asn-bgp", base, end, "64800")], replace_sources=("asn-bgp",))
    ingest(conn, [rec("asn-iptoasn", base, end, "64801")], replace_sources=("asn-iptoasn",))
    n_bgp = conn.execute("SELECT COUNT(*) FROM geoip WHERE source='asn-bgp'").fetchone()[0]
    n_ip = conn.execute(
        "SELECT COUNT(*) FROM geoip WHERE source='asn-iptoasn'"
    ).fetchone()[0]
    check("partial_refresh_keeps_other_source", n_bgp == 1 and n_ip == 1, (n_bgp, n_ip))


def case_cli_fixture() -> None:
    with tempfile.TemporaryDirectory(prefix="geoip-asn-test-") as td:
        td = Path(td)
        fixture = td / "fixture.csv"
        fixture.write_text(
            "asn-bgp,203.0.113.0,203.0.113.255,64500,BGP\n"
            "asn-iptoasn,203.0.113.0,203.0.113.255,64501,IPTOASN\n"
            "asn-geolite2,203.0.113.0,203.0.113.255,64502,GEO\n"
            "asn-bgp,2001:db8::,2001:db8::ffff,64700,BGP-V6\n"
            "asn-iptoasn,2001:db8::,2001:db8::ffff,64701,IPTOASN-V6\n",
            encoding="utf-8",
        )
        db = td / "geoip.sqlite"
        cmd = [
            sys.executable,
            str(Path(__file__).with_name("geoip_resolve_asn_bgp.py")),
            "--fixture",
            str(fixture),
            "--db",
            str(db),
        ]
        out1 = subprocess.run(cmd, capture_output=True, text=True, check=True)
        out2 = subprocess.run(cmd, capture_output=True, text=True, check=True)
        check("cli_fixture_reports_conflicts", "conflicts=2" in out1.stdout, out1.stdout)
        check("cli_fixture_second_run_same", "conflicts=2" in out2.stdout, out2.stdout)
        conn = sqlite3.connect(db)
        try:
            n4 = conn.execute(
                "SELECT COUNT(*) FROM geoip WHERE source LIKE 'asn-%'"
            ).fetchone()[0]
            n6 = conn.execute(
                "SELECT COUNT(*) FROM ipv6 WHERE source LIKE 'asn-%'"
            ).fetchone()[0]
            nconf = conn.execute(
                "SELECT COUNT(*) FROM panel_conflicts WHERE field='asn'"
            ).fetchone()[0]
        finally:
            conn.close()
        check("cli_fixture_v4_rows", n4 == 3, n4)
        check("cli_fixture_v6_rows", n6 == 2, n6)
        check("cli_fixture_conflicts_deduped", nconf == 2, nconf)
        # ASN selection on the CLI-created DB.
        conn = sqlite3.connect(db)
        try:
            m = merge_covering(load_covering(conn, "203.0.113.7"))
            m6 = merge_covering(load_covering(conn, "2001:db8::7"))
        finally:
            conn.close()
        check("cli_fixture_bgp_wins_v4", m.asn == "64500", m.asn)
        check("cli_fixture_bgp_wins_v6", m6.asn == "64700", m6.asn)


def main() -> int:
    case_cross_source()
    case_moas()
    case_more_specific()
    case_ipv6()
    case_anycast()
    case_partial_refresh()
    case_cli_fixture()
    total = 0
    print(f"geoip_asn_conflict_test: {'OK' if FAILS == 0 else f'{FAILS} FAILURES'}")
    return 0 if FAILS == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
