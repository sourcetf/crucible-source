#!/usr/bin/env python3
"""accept-verify-genconf.py — 从仓库 config-test.toml 生成隔离的验收配置。

- 端口整体平移到 23000+ 块（不碰 19095/18443/55555 等别人可能占用的口）
- DNS 端口显式化（23553/23153/23853），避免与别的 agent 的 5353/1953 撞
- root / docroot / lib / ssl 材料 改为绝对路径：这些字段在 `Config::resolve_paths`
  里按**配置文件所在目录**解析，而我们希望配置放在自己的 scratch 目录。
- geoip db_path / dns.dot / app.socket 保持相对（按进程 cwd=仓库根 解析）。
- 追加 4 个「高级」listener：proxy+page_rules / rate_limit / basic_auth / ip_access。

用法: python3 scripts/accept-verify-genconf.py [out.toml]
"""
import re, sys, os

REPO = "/home/dev123/crucible-git"
SRC = os.path.join(REPO, "config-test.toml")
# 工号 1009 / agent-verify2（wave-5）：端口块 26000+，状态根 scratch-verify2（与
# wave-3 的 23000/scratch-verify 隔离，避免与其他 agent 抢端口）。
OUT = sys.argv[1] if len(sys.argv) > 1 else "/home/dev123/scratch-verify2/conf/config-verify.toml"
SCRATCH = "/home/dev123/scratch-verify2"

PORTMAP = {
    "19095": "26095", "19081": "26081", "19445": "26445", "19446": "26446",
    "18443": "26443", "18444": "26444", "55556": "26556", "55555": "26555",
    "11853": "26853",
}

src = open(SRC).read()
for k, v in PORTMAP.items():
    src = re.sub(r"(?<![0-9])" + k + r"(?![0-9])", v, src)

# 显式 DNS 端口
src = src.replace("test_mode = true", "test_mode = true\nport = 26553\nrndc_port = 26153", 1)

# 需要绝对化的路径键（值形如 "xxx"，非绝对路径才加前缀）
ABS_KEYS = ("root", "docroot", "lib", "cert", "cert_ec", "key", "key_ec", "ech_keys")
def absify(m):
    key, val = m.group(1), m.group(2)
    if key in ABS_KEYS and not val.startswith("/") and not val.startswith("-----"):
        val = REPO + "/" + val
    return f'{key} = "{val}"'

src = re.sub(r'\b(root|docroot|lib|cert|cert_ec|key|key_ec|ech_keys)\s*=\s*"([^"]*)"', absify, src)

# ── 高级 listener（工号 1009 自建，用于 proxy / page_rules / rate_limit / ACL 验收）──
ADV = f"""

# ============ 验收用高级 listener（工号 1009 / agent-verify2）============

# proxy + page_rules + 响应/请求头改写
[[listeners]]
address = "127.0.0.1"
port = 26090
root = "{SCRATCH}/www-adv"
http_versions = ["h1", "h2"]
server_name = "adv.crucible.local"

[[listeners.proxy_rules]]
path = "/proxy"
upstream = "http://127.0.0.1:26099"
modify_request_headers = {{ X-Added-Req = "req-yes" }}
modify_response_headers = {{ X-Added-Resp = "resp-yes" }}

[[listeners.proxy_rules]]
path = "/ws"
upstream = "http://127.0.0.1:26099"

# WS 到 TLS h2 上游（上游 ALPN 广告 h2,http/1.1）——验证 force_h1（回源强制 h1）
[[listeners.proxy_rules]]
path = "/wss"
upstream = "https://127.0.0.1:26100"
ssl_mode = "no_verify"

# 代理到「无人在听」的上游 —— 验证错误映射不泄露内部路径
[[listeners.proxy_rules]]
path = "/dead"
upstream = "http://127.0.0.1:26199"

[[listeners.page_rules]]
match_url = "/old/*"
action = "rewrite"
target = "/new"

[[listeners.page_rules]]
match_url = "/redir/*"
action = "redirect"
target = "301:https://example.com/moved"

[[listeners.page_rules]]
match_url = "/hdr/*"
action = "header"
target = "X-Page: on"

[[listeners.page_rules]]
match_url = "/blocked*"
action = "block"

# 上传 + autoindex + 目录 301（root 含子目录；php app 用于 webshell 上传拦截探测）
[[listeners]]
address = "127.0.0.1"
port = 26094
root = "{SCRATCH}/www-up"
http_versions = ["h1", "h2"]
server_name = "up.crucible.local"

[listeners.autoindex]
enabled = true
enable_upload = true
paths = ["/"]

[[listeners.apps]]
paths = ["/php"]
enabled = true
engine = "php"
extensions = ["php", ""]
index = "index.php"
docroot = "{SCRATCH}/www-up/php"

# 限流：5 req/s，burst 5
[[listeners]]
address = "127.0.0.1"
port = 26091
root = "{SCRATCH}/www-rate"
http_versions = ["h1"]

[listeners.rate_limit]
enabled = true
rate_per_sec = 5.0
burst = 5.0

# 组合顺序：限流先于页面规则（h1 dispatch 顺序 rate → page_rules）
[[listeners.page_rules]]
match_url = "/blocked*"
action = "block"

[[listeners.page_rules]]
match_url = "/r/*"
action = "redirect"
target = "301:https://example.com/rd"

# 站点级 basic auth（口令 admin，复用 config-test 的 argon2id 哈希）
[[listeners]]
address = "127.0.0.1"
port = 26092
root = "{SCRATCH}/www-auth"
http_versions = ["h1"]

[listeners.basic_auth]
realm = "verify-auth"
username = "admin"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$E/RLobwgix2BWMRMT++urA$yEympjJtiDh0ezwSQsnkbsfYAoSzeDAHYw3EsUMBsj4"

# ip_access（明文）：只允许 10.0.0.0/8（本机 127.0.0.1 应被拒）——per-listener 档位
[[listeners]]
address = "127.0.0.1"
port = 26093
root = "{SCRATCH}/www-ip"
http_versions = ["h1"]

[listeners.ip_access]
allow = ["10.0.0.0/8"]
deny = []

# ip_access（TLS 面）：core2-wave4 报告点名「TLS/h3 请求路径仍走全局 ip_access」
# —— 用来回归 per-listener 档位在 TLS 面是否已接线。
[[listeners]]
address = "127.0.0.1"
port = 26096
root = "{SCRATCH}/www-tlsip"
http_versions = ["h1", "h2"]
server_name = "tlsip.crucible.local"

[listeners.ssl]
cert = "{REPO}/cert.pem"
key = "{REPO}/key.pem"
versions = ["TLSv1.2", "TLSv1.3"]

[listeners.ip_access]
allow = ["10.0.0.0/8"]
deny = []

# ip_access（h3 面）：h1+h2+h3 + TLS，per-listener ip_access 只允许 10/8。
[[listeners]]
address = "127.0.0.1"
port = 26097
root = "{SCRATCH}/www-h3ip"
http_versions = ["h1", "h2", "h3"]
server_name = "h3ip.crucible.local"

[listeners.ssl]
cert = "{REPO}/cert.pem"
key = "{REPO}/key.pem"
versions = ["TLSv1.2", "TLSv1.3"]

[listeners.ip_access]
allow = ["10.0.0.0/8"]
deny = []

# h3 目录 301 验证用：h1+h2+h3，root 含子目录（scratch，无 ACL）
[[listeners]]
address = "127.0.0.1"
port = 26098
root = "{SCRATCH}/www-h3dir"
http_versions = ["h1", "h2", "h3"]
server_name = "h3dir.crucible.local"

[listeners.ssl]
cert = "{REPO}/cert.pem"
key = "{REPO}/key.pem"
versions = ["TLSv1.2", "TLSv1.3"]
"""

src = src + ADV

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w").write(src)
print(f"wrote {OUT}")
