#!/usr/bin/env python3
"""Fetch GeoIP source layers into data/geoip/current/<NN-dir>/*.jsonl (标准 §2.1/2.2/2.4).

层目录 → 权重（geoip_merge.LAYER_WEIGHTS）：
  01-cloud (900)      rezmoss/cloud-provider-ip-addresses 聚合（jsDelivr 分厂商 JSON；
                      全量可 GEOIP_CLOUD_MODE=zip，~95MB）
  02-cloud-official (990) 官方 geofeed/JSON：AWS/GCP/Cloudflare/OCI/Vultr/Akamai/Linode
  05-hosting (300)    ipapi.is Hosting 免费 Sample（弱 IDC 兜底）
  10-isp-cn (400)     gaoyifan/china-operator-ip（电信/移动/联通/CERNET/CSTNET/鹏博士/
                      谷歌中国 CIDR；无城市，须与城市层交集；同段多运营商 → 整段丢弃）
  30-rir (600)        五大 RIR delegated-*-extended-latest（国家基线）

黑名单硬拒绝（§3）：Ip2Region / DB-IP 系 URL 一律不下载不合并（BLACKLIST_URLS）。
单源失败不影响其余；临时文件写完后原子改名。GEOIP_CLOUD_PROVIDERS 可改厂商清单。
"""

import ipaddress
import json
import os
import re
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAYERS = os.path.join(ROOT, "data", "geoip", "current")
UA = {"User-Agent": "crucible-geoip-sync/1.0 (+https://localhost)"}
TIMEOUT = 120

# §3 硬拒绝：这些源永不下载（历史权重戳见 geoip_purge_blacklisted.py）。
BLACKLIST_URL_PATTERNS = (
    r"ip2region",
    r"db-ip\.com|dbip",
)

# 默认云厂商清单（§2.1；GEOIP_CLOUD_PROVIDERS 覆盖，逗号分隔）。
DEFAULT_CLOUD_PROVIDERS = (
    "aws,azure,googlecloud,tencent,alibaba,huawei,oracle,cloudflare,"
    "digitalocean,vultr,github,linode,hetzner,ovhcloud,ibmcloud,scaleway,"
    "akamai,fastly,backblaze,baidu,zoom"
)

CHINA_OPERATOR_FILES = {
    "chinanet.txt": "中国电信",
    "cmcc.txt": "中国移动",
    "unicom.txt": "中国联通",
    "cernet.txt": "CERNET",
    "cstnet.txt": "CSTNET",
    "drpeng.txt": "鹏博士",
    "googlecn.txt": "谷歌中国",
}

CIDR_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})$")


def fetch(url: str) -> bytes:
    for pat in BLACKLIST_URL_PATTERNS:
        if re.search(pat, url, re.I):
            raise RuntimeError(f"blacklisted source refused: {url}")
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read()


def write_layer(dirname: str, filename: str, rows) -> int:
    out_dir = os.path.join(LAYERS, dirname)
    os.makedirs(out_dir, exist_ok=True)
    final = os.path.join(out_dir, filename)
    tmp = final + ".tmp"
    n = 0
    with open(tmp, "w", encoding="utf-8") as f:
        for row in rows:
            if not row.get("ip_start"):
                continue
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            n += 1
    os.replace(tmp, final)
    return n


def cidr_row(cidr: str, fields: dict) -> dict | None:
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None
    if net.version != 4:
        return None
    row = dict(fields)
    row["ip_start"] = str(net.network_address)
    row["ip_end"] = str(net.broadcast_address)
    return row


def parse_delegated(text: str, registry: str):
    """RIR delegated：registry|cc|type|start|count|date|status[|opaque]；只取 ipv4。"""
    for line in text.splitlines():
        if not line or line.startswith(("version", "%", "#")):
            continue
        parts = line.split("|")
        if len(parts) < 7 or parts[2] != "ipv4":
            continue
        cc = parts[1].upper()
        try:
            base = ipaddress.IPv4Address(parts[3])
            count = int(parts[4])
        except (ValueError, ipaddress.AddressValueError):
            continue
        if count <= 0:
            continue
        last = ipaddress.IPv4Address(int(base) + count - 1)
        yield {
            "ip_start": str(base),
            "ip_end": str(last),
            "country": cc,
            "registry": registry,
        }


# ------------------------------------------------------------- 01-cloud (900)

def walk_json_cidrs(node, out: list, extra: dict | None = None):
    """通用提取：递归收集 JSON 里一切 IPv4 CIDR 字符串，同对象 sibling 键作 region/service。"""
    extra = extra or {}
    if isinstance(node, dict):
        nxt = dict(extra)
        for k, v in node.items():
            kl = str(k).lower()
            if isinstance(v, str) and kl in ("region", "service", "scope", "provider"):
                nxt[kl] = v
            walk_json_cidrs(v, out, nxt)
    elif isinstance(node, list):
        for item in node:
            walk_json_cidrs(item, out, extra)
    elif isinstance(node, str):
        s = node.strip()
        if "/" in s and CIDR_RE.match(s):
            row = cidr_row(s, {})
            if row:
                row.setdefault("cloud_region", extra.get("region", ""))
                row.setdefault("cloud_service", extra.get("service", ""))
                out.append(row)


def do_rezmoss() -> int:
    """rezmoss/cloud-provider-ip-addresses：jsDelivr 分厂商 JSON。
    仓库布局未知细节 → 先探测 GitHub contents API 列出 JSON 文件再逐个解析。"""
    providers = os.environ.get("GEOIP_CLOUD_PROVIDERS", DEFAULT_CLOUD_PROVIDERS)
    want = {p.strip().lower() for p in providers.split(",") if p.strip()}
    api_base = "https://api.github.com/repos/rezmoss/cloud-provider-ip-addresses/contents/"
    rows: list = []
    seen = 0
    root = json.loads(fetch(api_base))
    dirs = [e["name"] for e in root if e.get("type") == "dir"]
    for pid in (want or dirs):
        if pid not in dirs:
            continue
        try:
            sub = json.loads(fetch(api_base + pid))
        except Exception as exc:
            print(f"warn: rezmoss {pid}: {exc}", file=sys.stderr)
            continue
        doc = None
        for entry in sub:
            nname = entry.get("name", "").lower()
            if nname == f"{pid}_ips.json" or (doc is None and nname.endswith(".json") and "ips" in nname):
                doc = json.loads(fetch(entry["download_url"]))
                break
        if doc is None:
            continue
        out: list = []
        walk_json_cidrs(doc, out)
        for row in out:
            row["cloud_provider"] = pid
        rows.extend(out)
        seen += 1
    if not seen:
        raise RuntimeError("rezmoss: no provider json parsed")
    return write_layer("01-cloud", "rezmoss.jsonl", rows)


# ------------------------------------------------------ 02-cloud-official (990)

def do_aws() -> int:
    doc = json.loads(fetch("https://ip-ranges.amazonaws.com/ip-ranges.json"))
    rows = []
    for p in doc.get("prefixes", []):
        if p.get("service") == "AMAZON":
            continue  # 伞前缀是其余服务的超集，跳过减少冗余重叠
        rows.extend(
            r for r in (
                cidr_row(p.get("ip_prefix", ""),
                         {"cloud_provider": "AWS", "cloud_region": p.get("region", ""),
                          "cloud_service": p.get("service", "")})
            ) if r
        )
    return write_layer("02-cloud-official", "aws.jsonl", rows)


def do_gcp() -> int:
    doc = json.loads(fetch("https://www.gstatic.com/ipranges/cloud.json"))
    rows = []
    for p in doc.get("prefixes", []):
        if not isinstance(p, dict):
            continue
        rows.extend(
            r for r in (
                cidr_row(p.get("ipv4Prefix", ""),
                         {"cloud_provider": "Google", "cloud_service": p.get("service", ""),
                          "cloud_region": p.get("scope", "")})
            ) if r
        )
    return write_layer("02-cloud-official", "google.jsonl", rows)


def do_cloudflare() -> int:
    text = fetch("https://www.cloudflare.com/ips-v4").decode("utf-8", errors="replace")
    rows = [r for r in (cidr_row(c, {"cloud_provider": "Cloudflare"}) for c in text.splitlines()) if r]
    return write_layer("02-cloud-official", "cloudflare.jsonl", rows)


def do_oci() -> int:
    doc = json.loads(fetch("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges/public_ip_ranges.json"))
    rows = []
    for region in doc.get("regions", []):
        rid = region.get("region", "")
        for p in region.get("cidrs", []):
            rows.extend(
                r for r in (
                    cidr_row(p.get("cidr", ""),
                             {"cloud_provider": "Oracle", "cloud_region": rid,
                              "cloud_service": p.get("tags", "")})
                ) if r
            )
    return write_layer("02-cloud-official", "oracle.jsonl", rows)


def do_vultr() -> int:
    # Vultr 官方 geofeed（constant.com）
    text = fetch("https://geofeed.constant.com/").decode("utf-8", errors="replace")
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "," not in line:
            continue
        cidr = line.split(",")[0].strip()
        r = cidr_row(cidr, {"cloud_provider": "Vultr"})
        if r:
            rows.append(r)
    return write_layer("02-cloud-official", "vultr.jsonl", rows)


def do_akamai() -> int:
    doc = json.loads(fetch("https://ipranges.akamai.com/json"))
    rows = []
    for p in doc.get("cidrs", []):
        r = cidr_row(p if isinstance(p, str) else p.get("cidr", ""),
                     {"cloud_provider": "Akamai"})
        if r:
            rows.append(r)
    return write_layer("02-cloud-official", "akamai.jsonl", rows)


def do_linode() -> int:
    text = fetch("https://geoip.linode.com/").decode("utf-8", errors="replace")
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "," not in line:
            continue
        cidr = line.split(",")[0].strip()
        r = cidr_row(cidr, {"cloud_provider": "Linode"})
        if r:
            rows.append(r)
    return write_layer("02-cloud-official", "linode.jsonl", rows)


# ---------------------------------------------------------- 05-hosting (300)

def do_ipapi_hosting() -> int:
    """ipapi.is Hosting 免费 Sample：GitHub 仓库探测 hosting 样例 CSV。"""
    api = "https://api.github.com/repos/ipapi-is/ipapi/contents/"
    listing = json.loads(fetch(api))
    target = None
    for entry in listing:
        n = entry.get("name", "").lower()
        if entry.get("type") == "file" and ("hosting" in n) and (".csv" in n or ".txt" in n):
            if "sample" in n or "free" in n:
                target = entry["download_url"]
                break
            target = target or entry["download_url"]
    if not target:
        raise RuntimeError("ipapi.is hosting sample not found in repo root")
    text = fetch(target).decode("utf-8", errors="replace")
    rows = []
    header: list[str] = []
    for line in text.splitlines():
        parts = line.strip().split(",")
        if not parts or not parts[0]:
            continue
        if parts[0].lower() in ("ip", "range", "cidr", "start") or "ip" in parts[0].lower():
            header = [p.strip().lower() for p in parts]
            continue
        if "/" in parts[0]:
            r = cidr_row(parts[0], {"hosting": "ipapi-hosting"})
        elif header and "start" in header and "end" in header:
            try:
                s = ipaddress.IPv4Address(parts[header.index("start")])
                e = ipaddress.IPv4Address(parts[header.index("end")])
                row = {"hosting": "ipapi-hosting", "ip_start": str(s), "ip_end": str(e)}
                if int(e) >= int(s):
                    rows.append(row)
                continue
            except (ValueError, IndexError):
                continue
        else:
            continue
        if r:
            rows.append(r)
        if len(rows) >= 200000:
            break  # Sample 兜底，封顶防失控
    return write_layer("05-hosting", "ipapi-hosting.jsonl", rows)


# ------------------------------------------------------------ 10-isp-cn (400)

def do_china_operator() -> int:
    """gaoyifan/china-operator-ip：CIDR 列表；同一 CIDR 被标成多个运营商 → 整段丢弃。"""
    base = "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/"
    per_isp: dict[str, list] = {}
    for fname, isp in CHINA_OPERATOR_FILES.items():
        text = fetch(base + fname).decode("utf-8", errors="replace")
        rows = []
        for cidr in text.splitlines():
            cidr = cidr.strip()
            if not cidr:
                continue
            r = cidr_row(cidr, {"isp": isp, "country": "CN"})
            if r:
                rows.append(r)
        per_isp[isp] = rows
    # 冲突丢弃：以 (ip_start, ip_end) 计数，>1 的整段丢。
    counts: dict[tuple[str, str], int] = {}
    for rows in per_isp.values():
        for r in rows:
            key = (r["ip_start"], r["ip_end"])
            counts[key] = counts.get(key, 0) + 1
    dropped = 0
    out = []
    seen: set[tuple[str, str]] = set()
    for rows in per_isp.values():
        for r in rows:
            key = (r["ip_start"], r["ip_end"])
            if counts[key] > 1:
                dropped += 1
                continue
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
    print(f"china-operator: dropped {dropped} multi-ISP overlapping ranges",
          file=sys.stderr)
    return write_layer("10-isp-cn", "china-operator.jsonl", out)


# --------------------------------------------------------------- 30-rir (600)

RIR_DELEGATED = {
    "apnic": "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}


def do_rir(registry: str, url: str) -> int:
    text = fetch(url).decode("utf-8", errors="replace")
    return write_layer("30-rir", f"delegated-{registry}.jsonl",
                       parse_delegated(text, registry))


def main() -> int:
    started = time.time()
    results: list[tuple[str, object]] = []

    for name, fn in (
        ("01-cloud/rezmoss", do_rezmoss),
        ("02-cloud-official/aws", do_aws),
        ("02-cloud-official/google", do_gcp),
        ("02-cloud-official/cloudflare", do_cloudflare),
        ("02-cloud-official/oracle", do_oci),
        ("02-cloud-official/vultr", do_vultr),
        ("02-cloud-official/akamai", do_akamai),
        ("02-cloud-official/linode", do_linode),
        ("05-hosting/ipapi", do_ipapi_hosting),
        ("10-isp-cn/china-operator", do_china_operator),
    ):
        try:
            n = fn()
            results.append((name, n))
        except Exception as exc:
            results.append((name, f"FAIL: {exc}"))

    for registry, url in RIR_DELEGATED.items():
        try:
            n = do_rir(registry, url)
            results.append((f"30-rir/{registry}", n))
        except Exception as exc:
            results.append((f"30-rir/{registry}", f"FAIL: {exc}"))

    ok = sum(1 for _, r in results if isinstance(r, int))
    for name, r in results:
        print(f"geoip_fetch_layers: {name} -> {r}")
    print(f"geoip_fetch_layers: {ok}/{len(results)} sources ok "
          f"in {time.time() - started:.1f}s")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
