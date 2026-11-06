# 投产与运维清单（Crucible）

> 状态：生产 1 实例、h1/h2/h3 + DNS（BIND / 可选 Unbound 递归）+ ECH 均正常。
> 本文档随代码版本化。**最后刷新：2026-10-31，HEAD `3245a03`（Wave-21b 收口）。**
> 配套：规格符合性矩阵 `.agents/1009/reports/spec-matrix.md`；最终缺口清单
> `.agents/1009/reports/spec-matrix-notes.md` §A；构建/运行/测试/门禁见 `README.md`。

---

## 0. 本版（Wave-18..22）相对上一版的**实质变化**

- **遗留栈**：NSS/TomCrypt 每已建立连接从 4 → **1 条 OS 线程**；SSLv2 为**完整 6 消息线协议**并与 OpenSSL 1.0.2u 互操作。
- **ECS 端到端**：新增 `[dns] recursor="unbound"`（默认 `bind` 零变化），把客户端 ECS 真正送到递归上游（见 ``README §8``）。
- **DNS 剩余项**：master `also-notify`、`rotation_days=0`=立即轮换一次、ACME `dns-01`、DoT 443 ALPN=dot/SNI 复用、可配 `ns_name`/`ns_glue`、旧绝对记录名一次性迁移、UI 去 SOA、ACME 失败日志去 HTML —— 全部收口。
- **TLS**：`trust_self_signed` 支持自定义 CA/指纹固定/mTLS；`prefer_tls13` 变为可观测；OCSP/ECH/PSK/0-RTT 端到端真机；tlsaudit2 修 12 个 TLS 主路径缺陷（非法套件不整口 soft-fail、root-first 链重排、OCSP unknown/revoked/超大响应不再装订等）。
- **性能**：FFI 池宽改为规格 `clamp(ncpu,2,4)`；引擎延迟/static 0.76–0.91（<1.1）；可选 `CRUCIBLE_APP_SANDBOX=1`/`CRUCIBLE_APP_UNLOAD=1`；`/__metrics` 新增 abandoned_workers/sandbox/libs_unloaded 计数。
- **孤儿 sidecar**：OpenBSD sysctl MIB 形态 + 启动清理判据修复，远程 SIGTERM/SIGKILL 均 **0 孤儿**。
- **新增旋钮/字段**：`reuse_port`/`reuse_port_workers`（SO_REUSEPORT 多 accept）、`connect_udp_framing`（auto/capsule/length/datagram）、
  `[admin] session_ttl_secs`（默认 28800=8h，绝对过期）、`geoip.path_priority_gain`、`geoip` 面板设置进 `data/geoip/panel.toml`。
- **远程部署**：生产曾部署到 `d389c56`/`47be71b`（四 feature、19 apps、真 Jetty、0 孤儿）；**Wave-21b 尚未上线**。

---

## 1. 部署与回滚（生产 OpenBSD 7.9，1 vCPU / 2GB / 根盘紧张）

**部署（锁内；共享树纪律）**：

```sh
mkdir /tmp/remote-build.lock
cd /crucible && git fetch origin main && git reset --hard <commit>
CARGO_BUILD_JOBS=1 cargo build --release --bin webserver \
  --features tls,tls_boring,go_shm_ipc,tls_nss,tls_tomcrypt
sh scripts/build_app_engines.sh --allow-missing
sh scripts/build_script_ffi.sh
cp -p target/release/webserver bin/webserver
sh /etc/rc.local                     # 或 kill -TERM $(pgrep -x webserver); sleep 2; sh /etc/rc.local
rmdir /tmp/remote-build.lock
```
- 预检：`./target/release/webserver --config /crucible/config.toml --check-config`（期望 `config OK: listeners=5, apps=18/19, tls acceptors built=3`）。
- `config.toml` 在生产是 **skip-worktree**（`git ls-files -v` 显示 `S`）；备份在 `/root/wave18-backup/`。**它不在 git 里**，回滚依赖备份。
- 磁盘：根盘常年 95%+，构建前确认 >900MB 可用；构建脚本末尾回收 dev 产物。

**回滚**：

```sh
# 只回滚二进制（最快）
cp -p /crucible/bin/webserver.bak-wave18-pre /crucible/bin/webserver
kill -TERM $(pgrep -x webserver); sleep 2; sh /etc/rc.local

# 完整回退（引擎 .so 与主二进制必须同代）
cd /crucible && git reset --hard <old-commit> && cargo build --release ... && \
  sh scripts/build_app_engines.sh --allow-missing && sh scripts/build_script_ffi.sh && \
  cp -p target/release/webserver bin/webserver && kill -TERM $(pgrep -x webserver); sleep 2; sh /etc/rc.local
```
- 换监听/端口配置后**必须显式 `kill $(pgrep -x named)`**：named 以 `-f` detached 常驻，只重启 webserver 不够。
- DNS 生效配置是 `state/dns/etc/panel.toml`（存在时整体覆盖 `config.toml` 的 `[dns]`）；备份/回滚该文件。

---

## 2. 日常运维

- **日志轮转**：`/etc/daily.local`（2MB/7 代、copytruncate）已覆盖 webserver 与 **named stderr** 两份；两份均 `O_APPEND`，copytruncate 安全。
- **健康/状态**：面板 `/__admin`（TLS 口）；`/api/overview`、`/__metrics`（默认 `metrics_public=false`，走 admin gate）；`state/native/**/sidecar.log`。
- **热载**：`SIGHUP` 或面板保存触发 `live_config`；DNS 记录改动触发 `reconcile`（BIND 重新生成 zone + `rndc reload`）。
- **引擎 sidecar**：php-fpm / JSP Jetty / ruby / rack / c(sidecar) 为**常驻子进程**，随 webserver 退出由 `child_registry` 回收；
  强杀（SIGKILL）时不清理属预期，重启后启动清理会回收（见 §3 孤儿项）。
- **构建产物**：JSP Fat JAR、ASP.NET managed DLL、TSX `node_modules/.bin/esbuild` 为 untracked，部署前必须重建。

---

## 3. 已知限制（必须知道的运维事实）

### 3.1 需要尽快修（P1，Wave-22 长稳/审计发现）

1. **Perl/PSGI 内存泄漏**：`/perl/` ~78 KB/req、`/psgi/` ~6.7 KB/req（`script_engine.c:1851/1883`、`psgi_engine.c:326`）。
   60 分钟混合负载下 RSS 到 6GB+，本机 8GB 护栏会在 40–50 分钟强杀。
   **运维缓解**：暂不把 `/perl/` `/psgi/` 放在高流量 listener；或定期轮换实例。根治见 notes CG-01。
2. **Admin 配置保存会丢上传配置**：`[listeners.autoindex]` 在 `paths=["/"]`（默认）时，`GET /api/config` 只回 `autoindex = true`，
   丢失 `enable_upload`/`upload_threads`；再在面板保存配置源码即把上传配置永久删掉（上传变 405）。
   **运维缓解**：把该 listener 的 `paths` 配成非默认（如 `["/", "/upload"]`），序列化器才会输出完整表。根治见 notes CG-02。

### 3.2 未实现 / 待产品决策（P2/P3）

- **服务端 mTLS 未实现**（无 `ssl.client_ca`/`client_auth`）。
- **产品自管 `recursor="unbound"` 不含 `validator`**：该模式不做 DNSSEC 验证（拿不到 `ad`）；要验证型递归用 named→外置 validator。
- **Ruby 嵌入默认关**：`/ruby/` 走常驻 sidecar（非 spawn-per-request，但也不是静态嵌入）。崩溃根因已修，可 `CRUCIBLE_ENABLE_RUBY_EMBED=1` 构建切换。
- **admin 面板缺 X-Frame-Options/CSP/nosniff/COOP**：Basic 凭据档存在点击劫持面（`SameSite=Strict` 会话 cookie 不受影响）。
- **`/tsx/` 405 不排空 body、不宣告 `Connection: close`**：并发大 POST 下客户端会 BrokenPipe/重试。
- **h2 `-m10` 多路复用 ≈0.36–0.38×h2o**（crate 级）；**TLS-h1 wrk 平均延迟**在开启访问日志的干净窗口 1.23–1.35（吞吐过线）。
- **无 per-IP 并发连接上限**；**rate_limit 按完整 IP 分桶**（持 /64 的 v6 客户端换地址可绕过）。
- **h2 缺 header 读超时**（h1 有 30s，h3 有 QUIC idle）：一条连接可长期占住最多 256 条半开流。
- **named 跨实例存活**（`-f` detached，设计行为）：若把「无 ppid=1 sidecar」当硬门禁会误判孤儿——按 cmdline/`CRUCIBLE_DNS_STATE_ROOT` 归属判定。
- **access_log 无 reopen/rotate API**：`SIGHUP` 只重载配置，外部 logrotate 的 rename 不会重开文件（`/etc/daily.local` 用 copytruncate 规避）。
- **`--check-config` 有副作用**：配 ECH 未给 `ssl.ech_keys` 时可能原地覆盖 `state/ech/ech_keys.pem`；配公共 CA + OCSP 会联网写 `state/ocsp`。**生产按 §5 始终显式配 `ssl.ech_keys`**。

### 3.3 部署/环境事实

- 生产组件与验收机不同：远程 `/aspnet/` 可能是 `aspnet-mini`（无 .NET 运行时）、`/go/` 是 prebuilt sidecar（无 Go 工具链）；
  「真 Jetty / 真 hostfxr / Go c-shared」是**验收机**（装了用户级运行时）的证据。
- `config.toml` 因缺生产 ECH 资产 `state/ech/real.pem` 会 `--check-config` rc=1（历史同）。
- 遗留栈需 `tls_nss,tls_tomcrypt` features + 用户级 NSS/libtomcrypt；默认构建完全不加载。

---

## 4. 需要你拍板 / 需要你操作的事项

### A. ECH 按 RFC 9849 部署（两张**不同**证书）

> ✅ 生产已于 2026-10-02 按 RFC 9849 部署：ECH 客户端拿**内层**证书，非 ECH 探测只拿**外层** cover；
> `dig … HTTPS` 返回的 `ech=` 解码后与 `state/ech/ech_config_list.bin` 逐字节相同。
> 你仍需做的：把占位域名换成真实域名（三处同名：`ssl.cert`/`cert_ec` 的 CN、`ssl.ech_public_name`、`[[https_rr]].name`，cover 要覆盖 `ech_public_name`）。

```sh
./bin/webserver --gen-cert crucible.local      --out-cert cover.pem --out-key cover.key.pem --days 3650
./bin/webserver --gen-cert prod.crucible.local --out-cert real.pem  --out-key real.key.pem  --days 3650
```
```toml
ssl = { cert="real.pem", key="real.key.pem", cert_ec="cert_ec.pem", key_ec="key_ec.pem",
        prefer_tls13=true, pqc=true, ech=true, ech_keys="state/ech/ech_keys.pem",
        ech_public_name="crucible.local",
        ech_cover_cert="cover.pem", ech_cover_key="cover.key.pem" }
```
- 本 BoringSSL 只有**一个** legacy credential 槽（`SSL_CTX_use_certificate` 覆盖语义）⇒ 内外层必须同密钥类型（本部署都用 EC；只提供 RSA 的客户端会失败=失败不泄漏）。
- `[[dns.https_rr]]` 必须写进 **`state/dns/etc/panel.toml`**（它整体覆盖 `config.toml` 的 `[dns]`），且必须存在覆盖该名字的 zone，否则记录被静默丢弃。
- 复验两条（缺一不可）：ECH 客户端 `ECH_ACCEPTED=true`+内层 CN；非 ECH 客户端只拿 cover 证书。

### B. admin 口令与暴露面

- ✅ **已配置**（2026-11-06）：`[admin] listeners_allow = [8443]` ⇒ 管理面只在 TLS 口可达（此前为空 =
  所有 listener 可达）。白名单外端口上 `/__admin` 回 **404**（不是 401 —— 401 会诱出浏览器
  Basic 口令框）。实测：`8443 /__admin`→401（唯一白名单口）。
- ✅ **明文应用口 9095 已移除**（2026-11-06）：18 条应用路由（/php /do /go …）迁到 **8443 TLS**，
  9095 不再监听（实测连接被拒）。原 9095 的 `file_open`/autoindex 策略随迁；`server_name` 由
  `apps.crucible.local` 变为 8443 的 `prod.crucible.local`（Host 不参与路由，仅影响 Location）。
- 引擎出网：**未收紧，保持原状**（`/etc/pf.conf` 与上游 53 都放开）。`scripts/harden-egress-pf.sh`
  是**可选**工具、默认**不部署** —— 53 是功能（DNS/DoT/DoH/ECS/应用解析），不是洞；
  2026-11-06 曾误当漏洞封掉引擎 53，已回滚。要收紧时必须把应用真正需要的端口（含 53）显式列入。
- 引擎已按应用分用户（`_c_<engine>` ×18）：跨应用 socket 连接与 `kill` 真机实测均被拒。
  创建/维护见 `scripts/create-engine-users.sh`，配置见各应用 `[listeners.apps.sandbox] user`。
- **建议尽快轮换生产 SSH root 口令**（历史明文口令曾散落本地副本）；推荐改密钥登录并关口令登录（先确认密钥能登再关）。

### C. `[dns]` 的唯一真相来源

`state/dns/etc/panel.toml` 存在时，`dns::effective()` 把它**整体**当作 DNS 配置，`config.toml` 的 `[dns]` 不生效。
二选一：① **以面板为准**（推荐，DoT/DoH 都在里面），在 config.toml 的 `[dns]` 上加注释说明；② 以 config.toml 为准（把 panel.toml 合并进去后移走它，并显式 `kill named` 重建）。

### F. DoT 对外策略

当前 `dot.allow=["0.0.0.0/0","::/0"]` 但 `recursion_acl=["127.0.0.1"]` ⇒ 公网 DoT 只做权威/根服务，**不给递归**（推荐保持）。
若要给公网递归：把 `recursion_acl` 扩到**具体网段**（**不要** `0.0.0.0/0`，开放递归是放大攻击帮凶）。

### J/N. 慢速资源占用 / 待决策（未改）

- **h2 缺 header 读超时**（h1 30s / h3 QUIC idle）；**rate_limit 按完整 IP 分桶**（v6 /64 可绕过 ⇒ 建议按 /64 聚合，属策略变更）。
- **DoH 空白名单即放行任意 Host**（且在所有 listener 含明文口可达）——是否「空白名单=拒绝」需你定。
- **`dns::effective()` 每 HTTP 请求一次磁盘读 + TOML 解析**（调用点在 h1/h2/h3 每请求）——OpenBSD FFS 秒级时间戳决定不能简单缓存。
- **无 per-IP/per-listener 并发连接上限**；**`metrics_public=true` 时 `/__metrics` 在所有 listener 可达**。
- **`ech_auto::ensure_material` 会原地覆盖运维放置的 ECH 材料**（含解析失败）——故**务必显式配 `ssl.ech_keys`**。
- 多条 GeoIP/面板低危项（面板每次 lookup 重开 SQLite+DDL、anycast 全表扫、`ensure_synced` 同步占 tokio worker、绝对路径回显）见 `.agents/1009/reports/spec-matrix-notes.md` §A.3。

### O. `--check-config` 的两条副作用（未修）

① 配 ECH 未给 `ssl.ech_keys` 时可能重写 `state/ech`；② 配公共 CA + OCSP 时会联网并在 `state/ocsp` 写缓存。
**建议**：按 A 节始终显式配 `ssl.ech_keys`；预检前先备份 `state/ocsp`。

---

## 5. 一键验收（构建完成后的判据）

```sh
unset CARGO_TARGET_DIR
cargo build --release --bin webserver --offline --features tls,tls_boring
bash scripts/build_app_engines.sh && bash scripts/build_script_ffi.sh

./bin/webserver --config config-test.toml --check-config        # rc=0
cargo test --release --bin webserver --offline --features tls,tls_boring   # wave21b: 662/0/1
sh scripts/accept-verify.sh --no-build                          # 302 PASS / 0 FAIL / 0 SKIP
python3 scripts/verify_app_engines.py                           # 38/38（默认 TLS 8443）
python3 bench/h2_fair_gate.py                                   # 官方双门禁 exit 0
python3 bench/app_engine_overhead.py --port 8443                # rust 延迟/static < 1.1
```
（遗留栈 PASS=7、DNS bind 72/0 + unbound 59/0 + gap 75/0 + DoT443 28/0 的命令见 `README.md §4`。）

---

## D. 已替你做完、只需确认（不需要动作）

- **开机自启与日志轮转**：`/etc/rc.local`、`/etc/daily.local` 已安装并随仓库版本化（`scripts/deploy/`）。
- **CONNECT-UDP 默认关**：要开在对应 listener 配 `connect_udp=true`（公网 UDP 中继面，建议同时配 `ip_access`/basic_auth）；
  `connect_udp_framing` 默认 `auto`（按对端能力协商 DATAGRAM/capsule/长度前缀）。
- **配置预检**：改动配置后先 `--check-config` 再重启（新校验误拒生产配置两次事故后的固定流程）。
- **磁盘**：长期 95%，构建脚本末尾回收 dev 产物；已 gzip 压缩 `state/dns/log/` 下废弃的 named.log（**未删除**，`zcat` 可读）。
