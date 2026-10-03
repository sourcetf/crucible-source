# 投产前清单（Crucible）

> 状态：生产 1 实例、h1/h2/h3 + DNS + ECH 均正常（ECH 已按 RFC 9849 真正落地，见 A）。
> 下面几项是**需要你拍板**的，
> 每项都给了可直接执行的步骤与复验判据（命令都在 `/crucible` 下跑）。
> 最后更新：见 git log（本文档随代码一起版本化）。

---

## A. ECH 按 RFC 9849 部署（需要**两张不同的**证书）

> **✅ 2026-10-02 已按 RFC 部署完成**（§21.34）。生产实测：ECH 客户端拿到**内层**证书
> （`prod.crucible.local`，指纹 `af6fca4d…`），非 ECH 客户端与只提供 ECDSA 的探测者只能拿到
> **外层** cover（`crucible.local`，指纹 `dbcc988e…`），两者不同；`dig @127.0.0.1 crucible.local
> HTTPS` 返回 `ech=`，且解码后与 `state/ech/ech_config_list.bin` **逐字节相同**。
> 证书在 `state/ech/`（`state/` 与 `*.pem` 都被 gitignore，私钥不入库），外层 EC 字段为
> `ssl.ech_cover_cert_ec`/`ech_cover_key_ec`（新增）。
>
> **你仍需做的只有一件事**：把占位域名换成真实域名（`*.crucible.local` 无法公网解析，
> 也没有 CA 会给它签证书 ⇒ 这套 ECH 只在「自建 DNS + 自签证书」的场景里成立）。
> 换的时候记得三处同名：`ssl.cert`/`cert_ec` 的 CN、`ssl.ech_public_name`、`[[https_rr]].name`，
> 并且 cover 要覆盖 `ech_public_name`；换完 `--check-config` 预检再重启。
>
> **两个坑（已在文档/代码里固化为检查）**：
> 1. `[[https_rr]]` 必须写进 **`state/dns/etc/panel.toml`**（它整体覆盖 `config.toml` 的 `[dns]`，
>    C-17），而且**必须存在覆盖该名字的 zone**（生产为此新建了 zone `crucible.local`）——
>    否则记录被静默丢弃（实测先 NXDOMAIN）。
> 2. 本 BoringSSL 只有**一个** legacy credential 槽（`SSL_CTX_use_certificate` 是覆盖语义，
>    `SSL_CREDENTIAL_*` 未导出）⇒ **每层只能服务一种密钥类型**。本部署两层都用 EC；只提供
>    RSA 的客户端会握手失败（**是失败不是泄漏**）。内/外层必须配成同一组密钥类型，
>    配置期已强制（`ssl.cert_ec` 与 `ssl.ech_cover_cert_ec` 同时配或同时不配）。

**（以下为部署前的原始说明，保留作为背景）**

**原现状**：8443 已开 `ech = true` + `ech_keys`（ECH 握手可用：探针 `ECH_ACCEPTED=true`），但
**内外层共用同一张自签 `cert.pem`**（CN=`crucible.local`、无 SAN），而内层真实名
`prod.crucible.local` 根本没有证书覆盖；DNS 里也没有 `[[dns.https_rr]]` 发布 `ech=`。
⇒ 「ECH 能用」但**外层伪装不存在**，且客户端拿不到 ECHConfig。

**步骤 1：生成两张证书**（用我们自己的二进制；不需要 openssl / bssl）：

```sh
cd /crucible
# 外层 cover：必须覆盖 public_name（当前 ECH 配置里的 public_name 是 crucible.local）
./bin/webserver --gen-cert crucible.local        --out-cert cover.pem --out-key cover.key.pem --days 3650
# 内层真实：覆盖真实站点名
./bin/webserver --gen-cert prod.crucible.local   --out-cert real.pem  --out-key real.key.pem  --days 3650
```

输出形如 `OK: CN=... SAN=... 有效期=3650天 证书=... 私钥=...(0600) sha256=...`；
私钥强制 0600（内层私钥泄露等于交出真实身份）。

**步骤 2：改 8443 的 ssl 配置**（`config.toml`）：

```toml
ssl = { cert = "real.pem", key = "real.key.pem", cert_ec = "cert_ec.pem", key_ec = "key_ec.pem",
        prefer_tls13 = true, pqc = true,
        ech = true, ech_keys = "state/ech/ech_keys.pem",
        ech_public_name = "crucible.local",                       # 外层名（= cover 覆盖的名字）
        ech_cover_cert = "cover.pem", ech_cover_key = "cover.key.pem",
        enable_nss = true, enable_tomcrypt = true }
```

构建期会 fail-fast 拦住的三种错配（不用你记）：
① cover 与真实证书是**同一张**（DER 相同）；② cover **不覆盖** `ech_public_name`；
③ cover 与静态 OCSP（`ssl.ocsp_der_path`）同时配（staple 是逐证书单份，必然错配一边）。

**步骤 3：预检 → 重启**

```sh
./bin/webserver --config /crucible/config.toml --check-config   # 必须先过
kill $(pgrep -x webserver); sleep 2; sh /etc/rc.local           # 或走面板保存触发 reload
```

（只改证书**文件内容**、配置字符串不变时不必重启：acceptor 指纹含材料 mtime/size，
下一次握手就会用新证书；但这次是**改配置**，要重启或 reload。）

**步骤 4：复验（两条都要，缺一不可）**

```sh
# ① ECH 客户端：必须接受，且拿到**内层真实证书**
./bin/ech_probe 127.0.0.1:8443 state/ech/ech_config_list.bin prod.crucible.local
#    期望 ECH_ACCEPTED=true、PEER_CN=prod.crucible.local

# ② 非 ECH 客户端（= 主动探测者视角）：只能拿到**外层 cover 证书**
./bin/ech_probe 127.0.0.1:8443 state/ech/ech_config_list.bin crucible.local --no-ech
#    期望 ECH_ACCEPTED=false、PEER_CN=crucible.local
```

第 ② 条就是「MITM / 探测者看不出真实域名」的判据 —— 只看第 ① 条会被
「标称成功但证书还是外层」骗过。

**步骤 5：把 ECHConfig 发布到 DNS**（不发布 = 客户端拿不到配置 = 等于没有 ECH）：

```toml
[[dns.https_rr]]
name = "crucible.local"      # 必须与 ech_public_name 一致
alpn = "h2,h3"
port = 8443
ech  = true                  # 值取自 state/ech/ech_config_list.bin（服务端实际在用的那份）
```

复验：`dig @127.0.0.1 crucible.local HTTPS +short` 应当含 `ech="AEX+DQ…"`。
注意：`state/dns/etc/panel.toml` 存在时 `[dns]` **以它为准**（见 C 项）。

---

## B. admin 口令（现在是随仓库分发的样例 `admin`）

**现状**：`config.toml` 里带着示例口令哈希（自述明文 `admin`），且 `[admin].listeners_allow` 未配置
⇒ 管理面在**所有** listener 上可达（含明文 HTTP 端口）。启动日志现在会告警。

> **✅ 2026-10-02 口令已轮换**：走面板 `POST /api/password` 换成 28 位随机口令
> （旧 `admin:admin` 实测 **401**、新口令 200），封存在 `/root/.crucible-admin-password`（0600）。
> **`listeners_allow` 仍未配置**（下面「同时建议」那一步）—— 那会改变你访问面板的端口，
> 属于工作流选择，留给你决定。

**步骤**（任选其一）：

1. 面板：登录 `/__admin` → 用户管理 → 改口令（服务端存 argon2id 哈希）。
2. 手改 `config.toml` 的 `password_hash`（新式 `[[admin.users]]`，或旧式 `[admin].password_hash`
   由启动时自动迁移）。

**同时建议**收紧暴露面：

```toml
[admin]
path = "/__admin"
realm = "WebServer Admin"
listeners_allow = [8443]      # 管理面只在 TLS 端口可达
```

**复验**：

```sh
curl -i -u admin:<新口令> https://127.0.0.1:8443/__admin/api/config/json   # 期望 200
curl -i -u admin:admin    https://127.0.0.1:8443/__admin/api/config/json   # 期望 401（旧口令失效）
curl -sk -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9095/__admin    # 配了 listeners_allow 后期望 404
```

---

## C. `[dns]` 的唯一真相来源（现在有两个，且 config.toml 那份是死的）

**现状**：`state/dns/etc/panel.toml` 存在时，`dns::effective()` 把它**整体**当作 DNS 配置，
config.toml 的 `[dns]` 从此不生效（启动日志已明确报出这件事）。**目前改 config.toml 的 `[dns]`
是无效操作**（含 `recursion_acl` 这类安全相关项）。

**两条路，选一条：**

1. **以面板为准**（推荐，因为面板已经改过、DoT/DoH 都在里面）：
   以后 `[dns]` 相关改动都在面板里做；在 config.toml 的 `[dns]` 上方加一行注释
   「本节的生效值是 `state/dns/etc/panel.toml`，勿在此修改」，避免下次又改错地方。
2. **以 config.toml 为准**：把 panel.toml 里的有效内容合并进 config.toml 的 `[dns]`，然后

   ```sh
   mv /crucible/state/dns/etc/panel.toml /crucible/state/dns/etc/panel.toml.bak
   kill $(pgrep -x webserver); sleep 2; sh /etc/rc.local
   named-checkconf -z /crucible/state/dns/etc/named.conf && echo named.conf OK
   dig @127.0.0.1 google.com A +short      # 解析仍正常
   dig @127.0.0.1 -p 853 …                 # DoT 仍在（若启用了 DoT）
   ```

   注意 panel.toml 里当前有 DoT 的 cert/key —— 合并时必须一起搬过去，否则 DoT 会静默起不来
   （现在配置期/生效配置侧都会告警）。

---

## D. 已经替你做完、只需你确认的（不需要动作）

- **开机自启与日志轮转**：`/etc/rc.local`、`/etc/daily.local`（2MB/7 代，copytruncate）已安装并在跑，
  两份都随仓库版本化（`scripts/deploy/`）。
- **CONNECT-UDP 默认关**：要开在对应 listener 配 `connect_udp = true`（公网 UDP 中继面，建议同时配
  `ip_access` / basic_auth）。
- **配置预检**：改动配置后可先 `./bin/webserver --config <cfg> --check-config` 验证再重启。
  这是「新校验误拒生产配置」两次事故后的固定流程。
- **磁盘**：长期 95%，构建脚本末尾会回收 `cargo check` 的 dev 产物；日志轮转已设上限。

## H. 日志轮转（审计 C-24：必须覆盖**全部写者**）—— 已修

**原问题**：`/etc/daily.local` 只轮转 `/var/log/crucible-restart.log`，**漏了 named**。
而 named 用 `-g` 前台跑（BIND 的 `-g` 会忽略 `logging` 配置的 file channel，强制所有日志走
stderr）⇒ `state/dns/log/named.stderr.log` 是 DNS 的**唯一**日志出口，且**无限增长**
（实测一天 2.4MB）。磁盘长期 95%，这是实打实的风险。

**已修**：`scripts/deploy/daily.local` 改为支持**多个日志**（`CRUCIBLE_LOGS` 列表，
默认含 webserver 与 named 两份），并已安装到 `/etc/daily.local`（与仓库版一致）。
两份都用 `O_APPEND` 打开 ⇒ copytruncate 安全（已在真实日志上实测：2.4MB → 归档 150KB、
文件归零、named 继续写、DNS 正常；归档 200/200 行无丢失、代数封顶 7）。

**顺带（已做）**：`state/dns/log/` 曾压着 ~14MB **已废弃**日志 —— `named.log`(3.6MB) +
`named.log.0`(5MB) + `named.log.1`(5MB)。它们是 BIND `logging` 的 file channel 产物，而 `-g`
模式下 BIND 根本不写它们（代码注释记录「自 9/9 起再没被写过」，实测三份的 mtime 都在 9 月）。
**没有删除**（生产数据、且不是我创建的），改为 **gzip 压缩**：13.8MB → 982KB，内容仍可
`zcat` 读回。要彻底清掉再执行：

```sh
rm -f /crucible/state/dns/log/named.log.gz /crucible/state/dns/log/named.log.0.gz /crucible/state/dns/log/named.log.1.gz
```

另外给维护循环加了一处**去重**：`dns: rootzone refresh failed` 与 `dnssec: rotation check failed`
此前会**每 30 秒**重打一条同样的 warn（失败路径不更新「上次成功」时间戳 ⇒ 持久失败就永久刷屏）。
现用 `warn_once(tag, msg)` 抑制**完全相同**的消息（消息变了仍会打）。

## I. 关于 `ssl.cert` + `ssl.cert_ec`（单证书槽的限制，改配置前先读）

本 build 的 BoringSSL（boring 5.2.0）**只导出单个 legacy credential 槽**：
`SSL_CTX_use_certificate` 是**覆盖**语义，未导出 `SSL_CREDENTIAL_*`。所以同一个 listener 里
**同时配 `cert`（RSA）与 `cert_ec`（EC）时，只有最后设置的那张生效**（当前是 EC 生效），
只提供 RSA 签名算法的客户端会握手失败（**失败，不是泄漏**）。

现状：生产只有 8443 配了 `cert_ec`，且已按 ECH 要求让内/外层**同为 EC**（配置期强校验
`ssl.cert_ec` 与 `ssl.ech_cover_cert_ec` 必须同时配或同时不配）。给其它 listener 加 `cert_ec`
前请知道这一点 —— 现代客户端普遍支持 ECDSA，影响面很小；要彻底消除得等 boring 暴露
`SSL_CREDENTIAL_*`。

---

## E. 53 端口对外服务（「把本机当根服务器」）—— **此前并未真正可用，现已修，只需你确认**

**背景**：`named.conf` 原本写 `listen-on port 53 { 0.0.0.0; 127.0.0.1; }`，但 BIND 会把**字面量
`0.0.0.0` 静默丢弃**（不建 socket、不打任何警告）⇒ 53 只在 `127.0.0.1` 上监听，外网一条查询都
收不到。也就是说「客户端把这个机子当根服务器」这件事，在修之前**只是本机自测通过**。
代码已改为生成关键字 `any`（`src/server/dns/mod.rs::listen_lists`，复盘见 WORKLOG 21.32）。

**你只需确认**（全部走 **TCP/TLS**：本机/本网 UDP/53 被运营商劫持 —— 向 `192.0.2.1` 发查询也返回
真实 A 记录，所以 UDP 的外部结果不可信）：

```sh
python _dnsq.py 83.229.125.81 .   NS 0 0 tcp          # 期望 qr aa；13 条根 NS + glue
python _dnsq.py 83.229.125.81 com. NS 0 0 tcp         # 期望转交 an=0 ns=13 ar=26
python _dnsq.py 83.229.125.81 com. DS 0 0 tcp         # 期望 qr aa，1 条 DS
python _dnsq.py 83.229.125.81 google.com A 1 0 tcp    # 期望「无 ra、无递归答案」= 外部递归关闭
python _dnsq.py 83.229.125.81 com. NS 0 0 tls         # DoT :853，期望同样拿到转交
```

机上自查：

```sh
fstat -p $(pgrep -x named) | grep ':53'               # 期望出现 83.229.125.81:53（UDP+TCP）
named-checkconf -z /crucible/state/dns/etc/named.conf && echo OK
dig +norec @127.0.0.1 . NS                            # 本机也应 aa + 13 条
```

**部署坑（下次别再踩）**：换监听/端口相关配置后，只重启 webserver **不够** —— `reconcile` 只判
「named 活着与否」，旧配置下 named 是活着的 ⇒ 它会继续用旧绑定。必须**显式 `kill $(pgrep -x named)`**，
让它按新生成的 named.conf 重建 socket。

**回滚**（本次部署的备份 stamp 为 `20261002-131111`）：

```sh
cd /crucible
cp -p bin/webserver.bak-20261002-131111 bin/webserver
cp -p state/dns/etc/named.conf.bak-20261002-131111 state/dns/etc/named.conf
kill $(pgrep -x webserver) $(pgrep -x named); sleep 2; sh /etc/rc.local
```

**回滚整个方案 A（自有根区 / 根服务器模式）**：DNS 的生效配置是 `state/dns/etc/panel.toml`
（见 C 项），它在上方案 A 之前的备份是 `state/dns/etc/panel.toml.bak-20261001`：

```sh
cd /crucible
cp -p state/dns/etc/panel.toml.bak-20261001 state/dns/etc/panel.toml
kill $(pgrep -x webserver) $(pgrep -x named); sleep 2; sh /etc/rc.local
named-checkconf -z state/dns/etc/named.conf && echo OK   # 回滚后仍是单实例 53
```

（回滚掉 A 会同时撤掉 `recursion_acl`、`[modes] root`、`[rootzone] enabled` —— 也就是撤掉
「递归走自有根」和「对外当根服务器」。若只想关掉其中一个，用面板改对应开关即可，不必整体回滚。）

---

## F. DoT 对外策略（**需要你决定**：公网 DoT 要不要给递归）

**现状**：`panel.toml` 里 `dot.allow = ["0.0.0.0/0","::/0"]`（面板意图：对所有人提供 DoT），
但 `recursion_acl = ["127.0.0.1"]`。合起来的效果是：**公网 DoT 客户端能连上、能问，但只拿得到根区
转交，拿不到递归答案**（对外的 DoT 目前是「根/权威服务器」，不是解析器）。

两条路：

1. **保持现状**（推荐，安全）：对外 DoT 只做权威/根服务。无需动作。
2. **对公网开递归**：把 `recursion_acl` 扩到**具体网段**。注意**不要**写 `0.0.0.0/0` ——
   开放递归是 DNS 放大攻击的帮凶（会被用来打别人），要开就只写固定客户网段。改完复验：
   `named-checkconf -z` + 从**外部** `python _dnsq.py 83.229.125.81 <外部域名> A 1 0 tls` 能拿到答案。

---

## G. 轮换生产 SSH root 口令（**建议尽快**：明文口令已在副本里扩散）

**现状**：生产 SSH 口令以**明文**散落在本地工作副本里 —— 两个根目录部署脚本（现已改造，见下），
以及**根目录约 269 个一次性 Python 脚手架**（`api1.py`、`b1.py`、`axfr*.py` …，都是历史会话留下的
SSH/同步小脚本）。本地快照仓库的基线提交（`caf3466`）还跟踪过其中一部分。生产配置里的
`config.toml` 也带着样例 admin 口令哈希（见 B 项）。

**已经做的缓解**（不需要你操作）：
- 两个部署脚本里的明文口令已移除，改为只从 `CRUCIBLE_SSH_PASSWORD` 读；未设置就拒绝运行；
  同时去掉了「在生产机上 `rm -rf` 后重建」和「把 `.git`/证书/`state/` 一起上传」的破坏性行为
  （审计 C-22）。正确的发布流程现在是入库的 `scripts/deploy/deploy_release.sh`。
- `.gitignore` 已把根目录 `*.py`/`*.ps1`/`*.sh` 脚手架整体忽略，防止再被提交进仓库。
- **被推送的仓库是干净的**：`git grep 'Yc4' HEAD` 在 `sourcetf/crucible-source` 上无命中，
  口令从未进过远端仓库。

**为什么仍要轮换**：上面几条只挡住「继续扩散」，挡不住「已经泄露」—— 明文口令只要落过一次盘
（工作副本、D 盘副本、任何备份）就应当视为已泄露。

**做法**（任选，推荐第 2 条）：

1. 换口令：生产上 `passwd` 改 root 口令，新口令只放环境变量
   `export CRUCIBLE_SSH_PASSWORD='...'`（不要写回脚本/文件）。
2. **改成密钥登录并关闭口令登录**（更彻底）：

   ```sh
   # 本机生成密钥
   ssh-keygen -t ed25519 -f ~/.ssh/crucible_ed25519 -C crucible-deploy
   # 用现口令把公钥装到生产，验证密钥能登，再关口令登录：
   #   生产 /etc/ssh/sshd_config:  PasswordAuthentication no
   #   rcctl restart sshd
   ```

   注意顺序：**先确认密钥能登，再关口令登录** —— 否则会把自己锁在外面（这条链路是唯一入口）。

**关于那些脚手架文件**：我不删除它们（不是本次任务的范围，也不确定是否还有人在用）；
它们不在版本控制里，轮换口令后里面写的旧口令也就没用了。要清理直接删即可。

---

## J. 本轮审计中**暂缓、需要你定**的三条

这三条都是真问题，但修法会**改变行为**（或属架构级），所以我没有擅自动手：

1. **`rate_limit` 按「完整 IP」分桶 ⇒ 持 /64 的 v6 客户端换个地址就能绕过**（每条新地址都拿到
   满桶）。改成**按 /64 聚合**是对的方向，但会连带改变现有 v4/v6 配置的限流粒度（同一 /64 下的
   不同客户端会互相挤占），属于策略变更 —— 你点头我再改。
2. **`env_lock`：引擎请求期间会**进程级**改环境变量（`setenv`/`unsetenv`），与其它线程的
   `getenv` 并发在 BSD/glibc 上是 UB**（`environ` 可能被 realloc）。模块里已经用
   `read_static_env` 把引擎热路径的读改掉了，但 admin/ACME/geoip 等请求路径仍在用
   `std::env::var`。彻底修法是给引擎改 `.env` 传递方式（架构级），不是一两行的事。
3. **h2 没有 header 读超时**（h1 有 30s，h3 有 QUIC idle 60s）：`h2.rs` 只在「读请求体」
   阶段有超时，`conn.accept()` 可以永久等一个不完整的 HEADERS ⇒ 一条连接可长期占住最多 256 条
   半开流（且不占在飞配额）。**h3 的同类问题**：全局在飞闸门在 `resolve_request()`（读 HEADERS）
   之后才获取 ⇒ 停顿的 HEADERS 不占配额。两者都属于「慢速资源占用」，修法是给 header 阶段加
   超时（h1 已有现成写法）。改动涉及 h2/h3 的连接生命周期，单独列出来做。
4. **h1 长连接沿用「建连时」的 listener 快照**：改 `basic_auth` / `root` / `page_rules` 对**已建立**
   的长连接不生效（直到它断开重连）。这与已修的上传闸门（C-4，改读 live 配置）是同一类；
   h1 的请求路径要改成「每请求重取 live 配置」，改动面比上传大，单独列出来。

---

## K. 第三轮审计中**记录但未改**的几条（低危 / 需脚本约定）

这些都是真的、但不是安全边界问题，改动会碰脚本约定或属性能优化，所以留档：

1. **GeoIP 面板每次 lookup 都重开 SQLite 并跑 DDL**（`geoip_panel/covering.rs::merge_pipeline`
   调 `db::open_panel("data/geoip/panel.sqlite")`）：它是**硬编码相对路径**（`CRUCIBLE_GEOIP_PANEL`
   与配置里的 db_path 都是死代码），且 `open_panel` 每次执行 `CREATE TABLE/ALTER TABLE`；
   整个调用发生在 tokio worker 上（未 `spawn_blocking`）。影响：每次面板查询都有同步文件 I/O + DDL。
   真正的修法是「连接缓存 + 移到 spawn_blocking」，但会动到面板 DB 的打开语义，先记。
2. **`anycast` 表每次 lookup 全表扫**（`geoip_panel/anycast.rs`，无 `LIMIT`/无 v6 判断）。
   种子表小的时候无害；导入大表后会变成每次查询一次全表读。
3. **`ensure_synced` 在周期任务里同步调用**（`server/mod.rs` 的 `tokio::spawn` 里直接调，
   内含最长 120s 的网络下载 + tar 解包）：admin 触发路径用了 `spawn_blocking`，周期任务没有。
   影响：一次同步会占住一个 tokio worker（该机只有 2 个）。
4. **updater 的 pid 文件与状态清理存在互删窗口**（`geoip_panel/ops.rs` 写 `update.pid`，
   `admin_geoip::handle_update_status` 在锁目录不存在时删它）：极端时序下面板会误报
   「更新已结束」。已在 Rust 侧补了**进程内** spawn 原子性，跨进程部分依赖脚本的锁约定。
5. **`admin_geoip::url_decode` 用 `byte as char`**：百分号编码的多字节 UTF-8 会被解成 Latin-1
   （值只进参数化 SQL 与白名单，所以是显示/筛选层面的正确性问题）。
6. **`headers_mod::append_security_headers` 是死代码**（无调用者）：全局的
   `X-Content-Type-Options`/`X-Frame-Options`/`Referrer-Policy` 因此只在少数路径出现。
   要不要全局加属于产品决策（会影响所有响应），先记。
---

## L. 第四轮的**更动**与**记录但未改**

### L.1 J 项里「`env_lock` 进程环境并发污染」的前提是错的，且已在第四轮修掉
J 项当时写的是「引擎写者都在锁内，只是进程 env 设计如此，需要操作员确认」。**事实不是**：
`apps/app_ffi.rs` 给 c/go/rust 留了一条「同线程内联、**跳过 env 锁**」的快路（§7.3），而它
拿 `.env` 变量的方式正是 C 侧 `appengine_apply_extra` 的 **setenv**
（`libs/app-engines/common/appengine_common.c`、samples/{c,rust}-plugin 都这么写）。
所以进程 env 有一个**完全不持锁、也从不恢复**的写者：
① 与别的引擎在锁内 install/restore 并发 ⇒ `environ` realloc 时别人的 `getenv` 踩已释放内存（UB）；
② 上一个应用的 `.env`（常含数据库口令/API key）会**永久留在进程环境**里，之后任何引擎的脚本
   都能 getenv 读到（跨应用泄密）。

第四轮删掉了这条快路：c/go/rust 现在与其它引擎同路（有界通用池 + `env_lock`）。
⇒ **J 项剩下的三条不动**（h1/h2 长连接快照、h2 缺 header 读超时、`rate_limit` 按完整 IP 分桶），
但「env_lock 并发污染」这条可以**划掉**了。

### L.2 第四轮**记录但未改**（每条都附了「为什么没改」）
1. **上传会话不校验属主**（`upload_resume.rs`：按 target 路径分键，`owner` 存了但**从不检查**）。
   任何客户端都能对**同一个路径**的上传会话续传/追加，闲置 30s 后还能 reset 截断别人的上传。
   没改的原因：这是**产品策略**——加属主校验会破坏「NAT 后换 IP」「多客户端协作上传」这两类
   正常用法，而上传区本来就是匿名可写设计。
2. **`commit` 只 fsync 文件、不 fsync 父目录**（`upload_resume.rs` 与 `admin_files.rs` 的 rename
   都是这一档）。崩溃紧跟在 rename 之后仍可能丢目录项。没改的原因：目录 fsync 要 `cfg(unix)`
   开目录再 fsync，且**是动到跨平台行为**（Windows 上会失败），需要单独一轮处理。
3. **`metrics_public = true` 时 `/__metrics` 在**所有** listener（含明文 HTTP 端口）可达** ——
   `[admin].listeners_allow` 只管 `is_admin_path`，指标路径不在其内。收紧会让现有抓取端断掉 ⇒
   策略决定。
4. **管理员用户名的存在性时间侧信道**（`basic_auth` / `check_admin_headers`）：字符串比较已经是
   恒时的，但**只有用户名命中才跑一次 argon2/yescrypt** ⇒ 响应时间可区分「用户是否存在」。
   抹平要在用户名不匹配时也跑一次假哈希（多用户时成本 ×N）⇒ 成本/策略取舍。
5. **`rate_limit` 的 `per_path` 桶用原始请求路径**：`//x`、`/./x`、`/%78`、`/x?` 各算一个桶 ⇒
   同一资源换写法就能倍增配额（尾斜杠已被 `trim_end_matches('/')` 处理）。修法是路径规范化，
   会改变限流粒度 ⇒ 行为变更。
6. **`type65_api` 只有内存表、没有任何消费者**：面板点「发布」得到 `published …`，但没有任何
   东西被写进 DNS 应答，且重启即丢。是否接进 `[[dns.https_rr]]`/ECH 流程属产品决策。
7. **`geoip_panel`/`dns::geoip` 的几条**（已在 K 项记过，第四轮复核仍然成立）：面板每次 lookup
   重开 SQLite + 跑 DDL 且同步跑在 tokio worker 上；`anycast` 表每次 lookup 全表扫；
   `ensure_synced`（含最长 120s 网络下载）在周期 async 任务里直接同步调用；
   `admin_geoip::url_decode` 的 `byte as char` 会把百分号编码的多字节 UTF-8 解成 Latin-1。
8. **C 引擎侧与 Rust 侧的环境过滤规则已经分叉**（报告，未改）：
   `appengine_common.c` 的 `setenv(key, val, 1)` 对键值**不做任何校验**，而 Rust 侧的
   `normalized()` 会滤掉空键/含 `=`/含 NUL 的项 —— 传给 C 的 extra JSON 用的是**未过滤**的
   `env_vars`。目前 `.env` 解析器把键限制在 `[A-Za-z0-9_]`（`deps.rs`）所以够不到，
   但两侧规则已经不一致，**任一侧放宽就是 `setenv` 拿到非法键名**。
   同理 `\uXXXX` 只取低 8 位落地（`ch = (char)(v & 0xff)`），值里的 NUL 会让 setenv 静默截断；
   Rust 侧 `parse_env_file` 不滤值中的 NUL。**改这里要动 vendored C 库并重新构建**，单独一轮做。
9. **`headers_mod::append_security_headers` 是死代码**（无调用者）：全局的
   `X-Content-Type-Options`/`X-Frame-Options`/`Referrer-Policy` 因此只在少数路径出现。
   要不要全局加会影响**所有**响应 ⇒ 产品决策。

### L.3 第四轮**明确不做**的两件（不要再提）
- **不给 `[dns]` 的 `recursion_acl`/`axfr_out_acl`/`dot.allow` 加条目级校验**：空串（唯一的
  **危险**方向，曾被当成「匹配所有地址」）已在第四轮改成 fail-closed；剩下的只是「拼错的条目
  静默不生效」= fail-closed 方向。而加校验就要维护 BIND 关键字白名单，本项目为此**被误拒
  打过两次**（第二轮第 14 条定调：与其加名字白名单，不如让真实代码路径报错）。
- **不动 h2/h3 里那个 `.header(LOCATION, ..).unwrap()`**：值的来源（`page_rules::apply_simple`，
  第四轮已加 `HeaderValue::from_str` 校验）与配置期（`safe_header_value`）已各拦一层。
  在没有第二处来源之前不再加层。
---

## M. 回归扫发现的**引擎环境缺件**（不是代码缺陷，是这台机器上没建/没装）

第四轮结束后的跨协议回归扫（`scripts/verify/regression_sweep.sh`）发现 `:9095` 上 18 个引擎路由里
有 7 个返回 502。逐条查了本地日志（**不脱敏**，原因写得很清楚），**全部是环境缺件**：

| 路由 | 日志里的原因 | 要可用需要做什么 |
|---|---|---|
| `/go/` | `libapp_go.so` 不存在 | `GO_ENGINE_MODE=shm bash scripts/build_app_engines.sh`（go 引擎走 shm 模式，与其它引擎不同一条构建路径） |
| `/jsp/`、`/do/` | `native sidecar sock not ready: state/native/9095-7-jsp/app.sock` | JSP 是**常驻侧车**；目前只有验收脚本会起它，生产没起。需要把 `libs/jsp-sidecar/jsp_sidecar.sh` 做成常驻（rc.local 或面板里配 sidecar/socket） |
| `/ruby/`、`/rack/` | `未嵌入 Ruby（not built with embedded MRI Ruby），且本机未安装 ruby/libruby` | 装 MRI + `rack` gem，然后带 `-DCRUCIBLE_HAVE_RUBY` 与 `pkg-config --cflags/--libs ruby` 重建 `libapp_ruby.so`/`libapp_rack.so` |
| `/psgi/` | `本引擎构建时未嵌入 Perl` | 装 Perl + `perl -MExtUtils::Embed -e ccopts/-e ldopts`，带 `-DCRUCIBLE_HAVE_PERL` 重建 `libapp_psgi.so` |
| `/tsx/` | `本机有 node 但没有 tsx` | tsx 的契约是「一键编译 + watch 部署」（编译产物交给静态路径或常驻 node 侧车），**不是**按请求执行 TypeScript。要可用得先编译并配侧车 |

**为什么这是设计行为、不是回归**：项目规格明确**禁止**「每请求 spawn 解释器」的 popen 回退
（理由在每个引擎的报错文本里都写了：每次请求起一个解释器既慢又不可控）。所以引擎不可用时
它**明确拒绝**（502 + 一条说清原因的日志），而不是静默退化成一个假响应 —— 后者更糟：
运维会以为引擎在跑。

**建议**：如果短期不打算补齐，就把 `config.toml` 里这些不可用的 `[[listeners.apps]]` 路由
**注释掉** —— 否则每次请求都会写一条 WARN 日志（`/go/` 之类被扫描时能刷得很快），
而且对外宣称了一个不存在的功能。
---

## N. 第五轮「记录但未改」（每条附理由；涉及行为变更或产品取舍）

1. **DoH 是 fail-open，而且不止在 TLS 面**：`doh_host_allowed` 的 Host 白名单**为空即放行任意
   Host**（`[dns.doh].hostnames` 缺省为空），而 h1/h2/h3 在**所有** listener（**含明文 HTTP 端口**）
   上都会命中 DoH 路径 ⇒ 面板一开 DoH，就等于在任意 Host、任意明文口上提供一个**递归解析端点**
   （RFC 8484 要求 DoH 走 HTTPS）。收紧 = 行为变更：会打断现在「空白名单也能用」的部署，
   也会打断 `config-test` 里把 DoH 指到明文 19095 的用例。**需要你定**：是「空白名单 = 拒绝」
   还是「保持放行但要求显式写 `*`」。
2. **`dns::effective()` 在每一个 HTTP 请求上做一次磁盘读 + TOML 解析**（调用点在 h1/h2/h3 的
   **每个**请求，不只是 DoH 请求）。要安全地缓存，失效判据只能是 panel.toml 的 mtime/size，
   而 **OpenBSD FFS 的时间戳只有秒级粒度** ⇒ 保存后 1s 内可能仍读到旧配置（这正是本项目反复
   踩过的「同一秒」坑）。所以宁可不缓存。真正的修法是「调用点先做廉价路径判断」或给 live 配置
   加一份带失效语义的 DNS 快照 —— 属结构调整，单独一轮做。
3. **DoT 成功路径的 info 日志**仍按事件写（握手 ok、每条查询的字节数）：完成握手的对端可以在
   单 IP 20/s 的额度内、多 IP 无上界地驱动 info 行。没改的原因：需要**完成 TLS 握手**才可达，
   且现场核对脚本可能 grep 这些行。要收口就降到 debug 或接同一套节流。
4. **`https_rr[].target` 未转义**（`https_rdata`，非引号位）：`target` 含 `"`/空白同样会让记录非法
   ⇒ 该 zone 被 named 拒载。**转义它没有合法语义**（TargetName 只能是域名或 `.`），只能二选一：
   拒绝（有误拒风险 —— 本项目被「新校验误拒」打过两次）或静默替换成 `.`（违背「不静默」）。
5. **`GET /api/dns/status` / `/api/dns/config` 回显 MaxMind `license_key`**：在 Basic 门之后，
   不算越权，但把一把密钥放进了 HTTP 响应体/浏览器缓存。是否脱敏属产品取舍。
6. **没有任何 per-IP / per-listener 并发连接上限**（`server/mod.rs` 的 accept 循环无界 spawn，
   `accept.rs` 也没有）。加限流属策略（阈值定多少、超限是拒绝还是排队）。
7. **`ech_auto::ensure_material` 会原地覆盖运维放置的 ECH 材料**：只要磁盘上
   `state/ech/ech_keys.pem` 的 ECHConfig 与当前 `ech_public_name`/`max_name_length`/套件不匹配
   （**包括解析失败**），就 `generate()` + `persist()` **原地覆盖**。若那份材料是运维放置且其
   ECHConfigList 已发布到 DNS，私钥即被销毁 ⇒ 客户端缓存的 ECHConfig 再也无法解密。
   改成「拒绝覆盖 / 覆盖前备份旧 key」会改变行为（ECH 从「静默重生」变成「报错不生效」），属策略。
8. **多个 TLS listener 配**不同**的 `ech_public_name` 时共用同一份 `state/ech/ech_keys.pem`**：
   每次 acceptor 构建都会互相覆盖（复用条件含名字相等 ⇒ 不同名就重生成），
   `state/ech/ech_config_list.bin` 与 DNS 里发布的 `ech=` 只对「最后跑的那个」成立。
   把 ECH public_name 定为**全局唯一**属策略决定。
9. **`h1/h2` 的 `dns::effective()` 之外**：`h2` 缺 **header 读超时**（h1 有 30s），
   `rate_limit` 按完整 IP 分桶（v6 /64 可绕过）—— 这三条是 J 项里剩下的，已在 J 节记录。
   **J 项的「已建立连接沿用旧 listener 策略」本轮已修**（见 WORKLOG §21.44），
   连同 `env_lock` 那条一起（第四轮已修），J 项现在只剩 h2 header 超时与 rate_limit 分桶两条。

### 顺带（更正一处历史记录）
第四轮把 `access.rs::cidr_or_exact` 的空串改成「永不匹配」（fail-closed）时，`config.rs` 里那句
描述运行期语义的注释也一并更正为「**任何**语义下空项都是错的」（旧语义：`allow` 放行所有人 /
`deny` 全站 403；现语义：封禁项静默失效）—— 那处已在**第四轮**的提交里，此处只是把结论记全。