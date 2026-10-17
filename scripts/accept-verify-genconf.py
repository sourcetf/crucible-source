#!/usr/bin/env python3
"""accept-verify-genconf.py — 从仓库 config-test.toml 生成隔离的验收配置。

- 端口整体平移到 36000+ 块（不碰 19095/18443/55555 等别人可能占用的口，
  也避开 24000/26000/28000/29000 等其它 agent/历史轮的端口块）
- DNS 端口显式化（36553/36153/36853），避免与别的 agent 的 5353/1953 撞
- root / docroot / lib / ssl 材料 改为绝对路径：这些字段在 `Config::resolve_paths`
  里按**配置文件所在目录**解析，而我们希望配置放在自己的 scratch 目录。
- geoip db_path / dns.dot / app.socket 保持相对（按进程 cwd=仓库根 解析）。
- 追加「高级」listener：proxy+page_rules / rate_limit / basic_auth / ip_access /
  per-site access_log / cgi_script(SCRIPT_NAME/PATH_INFO) / 假 ABI .so app。
- 同时生成 config-verify-ecsoff.toml（[dns] ecs=false，wave-7 ECS 不回显复核）。

用法: python3 scripts/accept-verify-genconf.py [out.toml]
"""
import re, sys, os

REPO = "/home/dev123/crucible-git"
SRC = os.path.join(REPO, "config-test.toml")
# 工号 1009 / agent-verify5（wave-9）：端口块 36000+，状态根 scratch-verify6
# —— 按本波任务书要求避开 24000/26000/28000/29000 段（历史 verify 轮的 29xxx 与
# 其它 agent 的 20xxx/21xxx/24xxx 均不冲突）。
OUT = sys.argv[1] if len(sys.argv) > 1 else "/home/dev123/scratch-verify6/conf/config-verify.toml"
SCRATCH = "/home/dev123/scratch-verify6"

PORTMAP = {
    "19095": "36095", "19081": "36081", "19445": "36445", "19446": "36446",
    "18443": "36443", "18444": "36444", "55556": "36556", "55555": "36555",
    "11853": "36853",
}

src = open(SRC).read()
for k, v in PORTMAP.items():
    src = re.sub(r"(?<![0-9])" + k + r"(?![0-9])", v, src)

# 显式 DNS 端口
src = src.replace("test_mode = true", "test_mode = true\nport = 36553\nrndc_port = 36153", 1)

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

# ============ 验收用高级 listener（工号 1009 / agent-verify3b）============

# proxy + page_rules + 响应/请求头改写
[[listeners]]
address = "127.0.0.1"
port = 36090
root = "{SCRATCH}/www-adv"
http_versions = ["h1", "h2"]
server_name = "adv.crucible.local"

[[listeners.proxy_rules]]
path = "/proxy"
upstream = "http://127.0.0.1:36099"
modify_request_headers = {{ X-Added-Req = "req-yes" }}
modify_response_headers = {{ X-Added-Resp = "resp-yes" }}

[[listeners.proxy_rules]]
path = "/ws"
upstream = "http://127.0.0.1:36099"

# WS 到 TLS h2 上游（上游 ALPN 广告 h2,http/1.1）——验证 force_h1（回源强制 h1）
[[listeners.proxy_rules]]
path = "/wss"
upstream = "https://127.0.0.1:36100"
ssl_mode = "no_verify"

# 代理到「无人在听」的上游 —— 验证错误映射不泄露内部路径
[[listeners.proxy_rules]]
path = "/dead"
upstream = "http://127.0.0.1:36199"

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

# §16.11 页面规则**匹配维度**（wave-6 独立复核：host/method/header）。
# 同一条规则必须在 h1/h2c（本 listener）与 h2(TLS)/h3（36098 listener）上判定一致；
# 判据见 page_rules.rs::rule_matches —— 维度缺失＝不匹配（绝不放宽成 path-only）。
[[listeners.page_rules]]
match_url = "/dimmeth*"
action = "block"
method = "POST"

[[listeners.page_rules]]
match_url = "/dimhost*"
action = "block"
host = "dim.crucible.local"

[[listeners.page_rules]]
match_url = "/dimhdr*"
action = "block"
header = "X-Dim: yes"

[[listeners.page_rules]]
match_url = "/dimall*"
action = "block"
method = "PUT"
host = "dim.crucible.local"
header = "X-Dim: yes"
priority = 7

[[listeners.page_rules]]
match_url = "/dimwild*"
action = "block"
host = "*.crucible.local"

# §16.11 页面规则优先级（wave-6 独立复核）：同路径两条规则，priority 大者先评估。
# 低优 301:/low 写在**前**，高优 308:/high 写在**后** —— 若 priority 未生效则首条(low)胜。
[[listeners.page_rules]]
match_url = "/dup*"
action = "redirect"
target = "301:/low"
priority = 1

[[listeners.page_rules]]
match_url = "/dup*"
action = "redirect"
target = "308:/high"
priority = 9

# 无 priority（等值 0）→ 保持配置顺序（首条 301:/first 胜）
[[listeners.page_rules]]
match_url = "/order*"
action = "redirect"
target = "301:/first"

[[listeners.page_rules]]
match_url = "/order*"
action = "redirect"
target = "308:/second"

# 上传 + autoindex + 目录 301（root 含子目录；php app 用于 webshell 上传拦截探测）
[[listeners]]
address = "127.0.0.1"
port = 36094
root = "{SCRATCH}/www-up"
http_versions = ["h1", "h2"]
server_name = "up.crucible.local"

[listeners.autoindex]
enabled = true
enable_upload = true
paths = ["/"]
# wave-8 复核：upload_threads 是**真闸门**（默认 4，clamp 1..=16）。这里显式给 16，
# 让「16 个在途上传」先撞 per-IP 会话配额（upload_resume::MAX_SESSIONS_PER_IP=16）
# 而不是提前撞本端口的并发闸门；配额跨端口按**来源 IP** 计（见 ext 的 8+8 用例）。
upload_threads = 16

[[listeners.apps]]
paths = ["/php"]
enabled = true
engine = "php"
extensions = ["php", ""]
index = "index.php"
docroot = "{SCRATCH}/www-up/php"

# 上传 RCE 闸门（sec2-wave5，wave-6 黑盒复核）：app docroot 内的运行期文件
# （init.sh / .env / deps/bin/index）即使扩展名闸门不拦，也绝不能经上传写进去。
# extensions 只给 "cgi"：PUT /cga/init.sh 不会路由到引擎，必落 upload 层 → 闸门判 403。
[[listeners.apps]]
paths = ["/cga"]
enabled = true
engine = "cgi"
extensions = ["cgi"]
index = "index.cgi"
docroot = "{SCRATCH}/www-up/cga"
lib = "{SCRATCH}/bin/libapp_cgi.so"

# ── per-child `.env`（wave-6 半成品复核）：cgi 引擎按子进程传 env，不再 setenv ──
# a=带 .env 慢请求（sleep 2）；b=无 .env 快；c=无 .env 慢（sleep 3）；d=带 .env 快。
# s = cgi_script（Rust spawn 路径，apply_clean_env）。
[[listeners.apps]]
paths = ["/enva"]
enabled = true
engine = "cgi"
extensions = ["cgi", ""]
index = "index.cgi"
docroot = "{SCRATCH}/env-www/a"
lib = "{SCRATCH}/bin/libapp_cgi.so"

[[listeners.apps]]
paths = ["/envb"]
enabled = true
engine = "cgi"
extensions = ["cgi", ""]
index = "index.cgi"
docroot = "{SCRATCH}/env-www/b"
lib = "{SCRATCH}/bin/libapp_cgi.so"

[[listeners.apps]]
paths = ["/envc"]
enabled = true
engine = "cgi"
extensions = ["cgi", ""]
index = "index.cgi"
docroot = "{SCRATCH}/env-www/c"
lib = "{SCRATCH}/bin/libapp_cgi.so"

[[listeners.apps]]
paths = ["/envd"]
enabled = true
engine = "cgi"
extensions = ["cgi", ""]
index = "index.cgi"
docroot = "{SCRATCH}/env-www/d"
lib = "{SCRATCH}/bin/libapp_cgi.so"

[[listeners.apps]]
paths = ["/envs"]
enabled = true
engine = "cgi_script"
extensions = ["cgi", ""]
index = "index.cgi"
docroot = "{SCRATCH}/env-www/s"

# ── cgi_script SCRIPT_NAME / PATH_INFO（wave-7 复核点）──
# /cgis/index.cgi            → SCRIPT_NAME=/cgis/index.cgi、PATH_INFO=""
# /cgis/index.cgi/extra/path → SCRIPT_NAME=/cgis/index.cgi、PATH_INFO=/extra/path
# （CGI/1.1 §4.1.13/§4.1.5；旧实现在第二种形态直接 404，且 SCRIPT_NAME 曾是文件系统路径）
[[listeners.apps]]
paths = ["/cgis"]
enabled = true
engine = "cgi_script"
extensions = ["cgi", ""]
index = "index.cgi"
docroot = "{SCRATCH}/env-www/cgis"

# ── 假 ABI .so（wave-7 复核点：ABI 自报符号的旧/新 .so 行为）──
# fake_abi_old.so 缺 appengine_abi_version（旧代产物）、fake_abi_bad.so 自报 99
# （版本不符）。两者都必须在**调用前**被拒：客户端 502、进程存活、绝无 marker 写入。
# docroot 里的 index.cgi 若被真的执行会写 marker 文件（由套件起服务前预置）。
[[listeners.apps]]
paths = ["/fakeabiold"]
enabled = true
engine = "cgi"
extensions = ["cgi", ""]
index = "index.cgi"
docroot = "{SCRATCH}/abi-www/old"
lib = "{SCRATCH}/bin/libapp_fake_abi_old.so"

[[listeners.apps]]
paths = ["/fakeabibad"]
enabled = true
engine = "cgi"
extensions = ["cgi", ""]
index = "index.cgi"
docroot = "{SCRATCH}/abi-www/bad"
lib = "{SCRATCH}/bin/libapp_fake_abi_bad.so"

# ── 第二上传口（wave-9 / wave-8 配额复核）：与 36094 同进程、不同 listener ──
# 用途：per-IP 会话配额是**跨端口按来源 IP** 计的。ext 用「36094 八个 + 36083 八个
# 在途」构造 16 在途，使第 17 个在**两个端口的 upload_threads 闸门都未满**的前提下
# 撞到 MAX_SESSIONS_PER_IP=16 → 503 + Retry-After: 5（精确指向会话配额，而非端口闸门）。
[[listeners]]
address = "127.0.0.1"
port = 36083
root = "{SCRATCH}/www-up2"
http_versions = ["h1", "h2"]
server_name = "up2.crucible.local"

[listeners.autoindex]
enabled = true
enable_upload = true
paths = ["/"]
upload_threads = 16

# 限流：5 req/s，burst 5
[[listeners]]
address = "127.0.0.1"
port = 36091
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
port = 36092
root = "{SCRATCH}/www-auth"
http_versions = ["h1"]

[listeners.basic_auth]
realm = "verify-auth"
username = "admin"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$E/RLobwgix2BWMRMT++urA$yEympjJtiDh0ezwSQsnkbsfYAoSzeDAHYw3EsUMBsj4"

# ip_access（明文）：只允许 10.0.0.0/8（本机 127.0.0.1 应被拒）——per-listener 档位
[[listeners]]
address = "127.0.0.1"
port = 36093
root = "{SCRATCH}/www-ip"
http_versions = ["h1"]

[listeners.ip_access]
allow = ["10.0.0.0/8"]
deny = []

# §16.12 per-site 访问日志覆盖（wave-6 半成品复核）：全局 [access_log].enable=true，
# 本 listener 配 enable=false —— 生效则打本口的请求**不得**出现在 webserver.log。
# （root 必须与其他 listener 不同：config 校验拒绝「同 root 多 listener」。）
[[listeners]]
address = "127.0.0.1"
port = 36087
root = "{SCRATCH}/www-alog"
http_versions = ["h1"]

[listeners.access_log]
enable = false

# §16.12 per-site 访问日志 level（wave-7 复核）：全局 level=info，本 listener 覆盖
# level="debug" —— 历史缺陷是「选 debug/trace 反而一行都不落盘」（env_logger 默认
# info 过滤）。当前实现有意让 level 只做配置/展示、落盘统一，故打本口的请求必须**照常**
# 出现在 webserver.log（由 ext 套件断言）。root 必须与其它 listener 不同。
[[listeners]]
address = "127.0.0.1"
port = 36088
root = "{SCRATCH}/www-alog3"
http_versions = ["h1"]

[listeners.access_log]
level = "debug"

# —— 用来回归 per-listener 档位在 TLS 面是否已接线。
[[listeners]]
address = "127.0.0.1"
port = 36096
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
port = 36097
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
# 另承载：页面规则维度（h1/h2TLS/h3 三面同判）与 h3 GOAWAY 在飞请求（/slow 慢上游）。
[[listeners]]
address = "127.0.0.1"
port = 36098
root = "{SCRATCH}/www-h3dir"
http_versions = ["h1", "h2", "h3"]
server_name = "h3dir.crucible.local"

[listeners.ssl]
cert = "{REPO}/cert.pem"
key = "{REPO}/key.pem"
versions = ["TLSv1.2", "TLSv1.3"]

[[listeners.proxy_rules]]
path = "/slow"
upstream = "http://127.0.0.1:36099"

[[listeners.page_rules]]
match_url = "/dimmeth*"
action = "block"
method = "POST"

[[listeners.page_rules]]
match_url = "/dimhost*"
action = "block"
host = "dim.crucible.local"

[[listeners.page_rules]]
match_url = "/dimhdr*"
action = "block"
header = "X-Dim: yes"

[[listeners.page_rules]]
match_url = "/dimall*"
action = "block"
method = "PUT"
host = "dim.crucible.local"
header = "X-Dim: yes"
priority = 7

[[listeners.page_rules]]
match_url = "/dimwild*"
action = "block"
host = "*.crucible.local"
"""

src = src + ADV

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w").write(src)
print(f"wrote {OUT}")

# ── 变体：dns ecs=false（wave-7「ecs=false 不回显」复核）──
# config-test.toml 的 [dns] 没有显式 ecs 键（默认 true）。插入 ecs = false 后作为
# 独立实例的配置；只在 PASS2.1 用它（跑完就停），其余趟次用主配置。
if "[dns]" in src and "\necs = false" not in src:
    variant = src.replace('enabled = true\nlisten_addr = "any"',
                          'enabled = true\nlisten_addr = "any"\necs = false', 1)
    vpath = os.path.join(os.path.dirname(OUT), "config-verify-ecsoff.toml")
    open(vpath, "w").write(variant)
    print(f"wrote {vpath}")
