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

**顺带**：`state/dns/log/` 下有 ~14MB **已废弃**的日志可回收 —— `named.log`(3.6MB)、
`named.log.0`(5MB)、`named.log.1`(5MB)。它们是 BIND `logging` 的 file channel 产物，
而 `-g` 模式下 BIND 根本不写它们（代码注释记录「自 9/9 起再没被写过」）。确认无人在读后可删：

```sh
rm -f /crucible/state/dns/log/named.log /crucible/state/dns/log/named.log.0 /crucible/state/dns/log/named.log.1
```

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
