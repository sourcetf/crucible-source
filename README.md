# Crucible WebServer

单进程、以 Rust + Tokio 为核心的高性能 Web 服务器：HTTP/1.0–1.1、HTTP/2（h2c + TLS）、HTTP/3（QUIC）、
TLS/遗留协议栈、内嵌应用引擎、权威/递归 DNS、GeoIP 精细面板与 Admin WebUI。

- 时间基准：**2026-10-31，HEAD `3245a03`（Wave-21b 收口）**。规格符合性矩阵见
  `.agents/1009/reports/spec-matrix.md`（✅323 / ⚠️8 / ❌0 / 🔵10），最终缺口清单见 `.agents/1009/reports/spec-matrix-notes.md` §A。
- 投产前待办/运维决策见 `OPERATOR-TODO.md`。

---

## 1. 目录 / 关键路径

| 路径 | 说明 |
|---|---|
| `src/server/**` | HTTP/1、h2、h3、TLS、DNS、Admin、GeoIP 面板、引擎调度 |
| `libs/h2/**` | vendored h2 framed_write（BATCH_CAP/coalesce 开关） |
| `libs/quinn-boring/**` | QUIC/BoringSSL 集成 |
| `libs/tls-nss/**`、`libs/tls-tomcrypt/**` | 遗留栈（NSS / TomCrypt）shim |
| `libs/app-engines/**`、`libs/script-ffi/**` | 各引擎 `.so` 与解释器嵌入 |
| `www-apps/**` | 引擎样例（php/c/go/rust/lua/…/c 的 pthread sidecar） |
| `scripts/**` | 构建、部署、验收、DNS/GeoIP 工具 |
| `bench/**` | 性能门禁脚本 |
| `config.toml` / `config-test.toml` | 生产样例 / 测试样例配置 |

---

## 2. 从零构建

### 2.1 环境

```sh
. /home/dev123/bin/buildenv.sh      # 本机固化环境：TMPDIR/PATH/CARGO_TARGET_DIR/BoringSSL 路径等
unset CARGO_TARGET_DIR              # 构建 release 时必须：避免 dev/release 产物串用（§12 坑 1）
```

说明：`buildenv.sh` 已导出 `BORING_BSSL_PATH`/`BORING_BSSL_INCLUDE_PATH`/`LIBCLANG_PATH`。
应用运行时（PHP/Ruby/Perl/JDK/Node/.NET/Go/BIND/Unbound）为用户级安装在 `~/local`：
`. /home/dev123/local/crucible-runtimes.env`（缺它时 php/tsx/jsp/do 等会 503/502）。

### 2.2 主二进制

```sh
# 默认（BoringSSL 主路径）
cargo build --release --bin webserver --offline --features tls,tls_boring

# 带遗留栈（NSS + TomCrypt；需用户级 NSS 头/库与 libtomcrypt）
NSS_PREFIX=$HOME/local/usr \
cargo build --release --bin webserver --offline \
  --features tls,tls_boring,tls_nss,tls_tomcrypt

# OpenBSD 生产另加 go_shm_ipc（Go 引擎 shm 模式）：
#   --features tls,tls_boring,go_shm_ipc,tls_nss,tls_tomcrypt
```

产物：`target/release/webserver`（约 20–21 MB）。`scripts/build_release.sh --restart` 封装了
「unset TARGET_DIR + 构建 + 换二进制 + 重启」；LTO **默认 thin**（`Cargo.toml:106`），`--fat`/`--thin` 可切换。

### 2.3 应用引擎与 sidecar

```sh
bash scripts/build_app_engines.sh              # 产出 19 引擎 .so + jsp-sidecar.jar + ASP.NET 样例
bash scripts/build_script_ffi.sh               # Python/Perl(/Ruby) 解释器嵌入
bash scripts/build_jsp_sidecar.sh              # 真 Jetty+Jasper Fat JAR（需 javac 在 PATH，JDK17+）
```
- 全新离线机需先装运行时（`scripts/install_app_runtimes.sh`）。
- 远程/离线机器可用 `--allow-missing` 降级（会如实点名缺失项，不伪造成功）。
- JSP JAR / ASP.NET managed DLL / TSX `node_modules/.bin/esbuild` 是 **untracked 构建产物**，部署前必须重建（见 notes R-09）。

---

## 3. 运行

```sh
./bin/webserver --config config.toml --check-config   # 预检（必须先过）
./bin/webserver --config config.toml                  # 前台运行
# 或：scripts/build_release.sh --restart（/etc/rc.local 拉起，日志 /tmp/webserver-restart.log）
```
- 配置热重载：`SIGHUP` 或面板保存（`live_config`；Admin HTML 例外，改 UI 必须重链）。
- 端口约定（样例 `config.toml`）：`9081/9095` 明文 h1+h2c、`9445` 仅 TLS1.2、`9446` 仅 TLS1.3、
  `8443` TLS1.2+1.3+h2+h3、`853` DoT、`53` named、`8443/udp` h3。
- `[admin].listeners_allow` 可把管理面收到 TLS 口；明文登录只在 TLS 签发 cookie。

---

## 4. 测试

```sh
# 单测（当前共享树在 wave21b 收口记录 662 passed / 0 failed / 1 ignored）
cargo test --release --bin webserver --offline --features tls,tls_boring

# 全量黑盒验收（6 段，约 8.5 分钟）→ 302 PASS / 0 FAIL / 0 SKIP
sh scripts/accept-verify.sh --no-build

# 19 引擎 × h1+h2c → 38/38
python3 scripts/verify_app_engines.py --port 9095

# 遗留 TLS（需四 feature 二进制）→ PASS=7
CRUCIBLE_BIN=target/release/webserver CRUCIBLE_TLS_TEST_PORT=19543 sh scripts/test_tls_stacks.sh

# DNS 真机（一条命令两档）→ bind 72/0 + unbound 59/0
export PATH=$HOME/local/usr/bin:$HOME/local/usr/sbin:$PATH
DNSV_BIN=target/release/webserver bash scripts/dns_verify.sh --real both
bash scripts/dns_gap_verify.sh          # DNS 剩余项 75/0
bash scripts/dns_dot443_verify.sh       # DoT 443 SNI/ALPN 复用 28/0
```

---

## 5. 性能门禁

规格口径：**plain-h1 用官方 `bench/h2_fair_gate.py` 的 wrk 分支**（`wrk -t2 -c64 -d10s --latency`，
双门禁 `h2o/ours ≤1.2` 且 `ours/h2o ≤1.2`）。

```sh
python3 bench/h2_fair_gate.py                      # 官方双门禁（wrk 分支；exit 0 = PASS）
python3 bench/app_engine_overhead.py --port 9095   # 引擎 RPS/延迟（rust/c/go vs static）
python3 bench/tls_matrix_h2o.py --ours <bin> --h2o <h2o> \
  --rounds 5 --duration 10 --cpu-ours 8-13 --cpu-h2o 14-19 --cpu-client 20-29 --handshake
```
实测（见 reports）：plain-h1 官方 wrk 双门禁 PASS、exit 0；引擎延迟/static **rust 0.76–0.91、c 0.75–0.90、go 0.82–1.09**（<1.1）；
RPS rust/c/go 51–67k（门槛 11k/9k）。
**已知未达标项**：`tls12-h1`/`tls13-h1` 的 **wrk 平均延迟**在干净窗口 1.23–1.35（吞吐过线；主因是门禁期访问日志 ON）；
**h2 `-m10` ours/h2o ≈0.36–0.38**（crate 级架构限制，见 notes §B 与 4 条替代路线）。

---

## 6. 引擎矩阵

- 19 路由 × h1+h2c = **38/38 200**：php / c / go / rust / lua / python / ruby / perl / wsgi / asgi / psgi /
  rack / cgi / uwsgi / asp / aspnet / jsp / do / tsx。
- 真组件证据：JSP/do = 真 Jetty 11.0.24（UDS sidecar）、ASP.NET = hostfxr/CoreCLR 10.0.13、
  Go = c-shared FFI、PHP = php-fpm、Ruby = 常驻 sidecar、C = pthread-per-conn UDS sidecar（无 `.so` 时）。
- 引擎 `.so` 由 `libs/app-engines/**` 构建；分发顺序 **FFI `.so` → 显式存活 UDS → `deps/bin/index` sidecar → 502**（无 per-request CGI 回退）。
- 可选旋钮：`CRUCIBLE_APP_POOL_WIDTH`（FFI 池宽，默认 `clamp(ncpu,2,4)`）、
  `CRUCIBLE_APP_SANDBOX=1`（引擎子进程隔离，默认白名单 lua）、`CRUCIBLE_APP_UNLOAD=1`（非解释器引擎真 dlclose，默认关）。

---

## 7. 遗留栈（SSLv2/SSLv3/IE6）

- 构建期用 `--features tls_nss,tls_tomcrypt`；默认构建**完全不加载** NSS/TomCrypt（`ldd`/`strings`/运行日志 `legacy=none`）。
- BoringSSL 直路径；ClientHello 路由决定是否进 NSS（SSLv3、IE6 v2-compatible hello）或 TomCrypt（SSLv2 完整 6 消息状态机）。
- 已建立连接 **1 条 OS 线程/连接**（NSS/TomCrypt），握手期 10s 绝对 deadline + 128 并发上限。
- 验证：`test_tls_stacks.sh` PASS=7；与 OpenSSL 1.0.2u（`enable-ssl2`）互操作通过。

---

## 8. DNS 后端选择

`[dns] recursor` 只接受两值：

- **`"bind"`（默认，零变化）**：BIND named 同时做权威（KASP/DNSSEC/NSEC3/AXFR/IXFR/RPZ）与递归/转发。
  已知限制：BIND 9.20 递归时**丢弃 ECS**（只透传 COOKIE），所以「把客户端 ECS 送到真实递归上游」在 bind 模式不成立。
- **`"unbound"`**：Unbound 占主端口做公网递归前端（`send-client-subnet` + `subnetcache` 把客户端 ECS 原样送上游），
  BIND 退到内部权威端口（`[dns.unbound].auth_port`，默认 `port+1`）继续负责签名/KASP/AXFR。
  配置示例：

```toml
[dns]
enabled = true
recursor = "unbound"
forwarders = ["192.0.2.53"]
ecs = true
[dns.unbound]
auth_port = 5354
send_client_subnet = true
```

- 真机：`scripts/dns_verify.sh --real both` → bind 72/0 + unbound 59/0；伪上游抓到客户端 ECS（`203.0.113.0/24`）。
- **注意**：`state/dns/etc/panel.toml` 存在时它会**整体覆盖** `config.toml` 的 `[dns]`（改 config 的 `[dns]` 无效，除非先移走 panel.toml）。
- 已知未闭：产品自管的 unbound **不含 `validator` 模块** ⇒ 该模式不做 DNSSEC 验证（拿不到 `ad`）；要验证型递归用 named→外置 validator 拓扑（见 notes CG-04）。
- geoip 分线路与 unbound 互斥（Unbound 无 view/match-clients），`--check-config` 会拒绝。

---

## 9. 常见坑

1. **构建 release 前必须 `unset CARGO_TARGET_DIR`**（否则 dev 产物污染）。
2. **`config.toml --check-config` 可能 rc=1**：缺生产 ECH 资产（`state/ech/real.pem`）；用 `config-test.toml`（rc=0）做开发。
3. **改 Admin HTML 必须重链**（`include_str!` 编入二进制）。
4. **JSP/sidecar 是常驻进程**，未构建 JAR 时 `/jsp/` `/do/` 会明确 502（不是静默降级）。
5. **换监听/端口后只重启 webserver 不够**：DNS named 以 `-f` detached 常驻，需显式 `kill $(pgrep -x named)`。
6. **`--check-config` 有副作用**：配 ECH 未给 `ssl.ech_keys` 时可能原地覆盖 `state/ech/ech_keys.pem`；配公共 CA + OCSP 时会联网写 `state/ocsp`。生产按 A 节始终显式配 `ssl.ech_keys`。
7. **`www-apps/*/deps` 是共享目录**，无某运行时的实例可能重建它（init.sh 已加绝对路径兜底）。
8. **浏览器会话 cookie 是持久 cookie**（`Max-Age`/`Expires` 与服务端绝对过期一致）；持续访问不续期。
9. **TLS1.3 会话恢复**：BoringSSL 在首个应用写之后才发 NewSessionTicket —— 只握手不发请求看不到 ticket。
10. **`pqc=false` 不禁用 BoringSSL 默认 PQ 组**（`X25519MLKEM768`）；要关必须显式配 `ssl.groups=["X25519","P-256","P-384"]`。

---

## 10. 已知限制（详见 `spec-matrix-notes.md` §A）

- **P1**：Perl 引擎每请求 `perl_parse`+`perl_run` 泄漏 ~78 KB/req、PSGI ~6.7 KB/req（60 分钟 soak 被 8GB 护栏强杀）；
  Admin 全量配置保存 round-trip 丢弃 `[listeners.autoindex]` 的 `enable_upload`/`upload_threads`（保存后上传变 405）。
- **P2**：服务端 mTLS 未实现；产品自管 unbound 缺 validator（拿不到 `ad`）；Ruby 嵌入默认关（走 sidecar）；
  admin 面板缺 XFO/CSP/nosniff/COOP；`/tsx/` 405 不排空 body/不宣告 close。
- **架构/环境**：h2 `-m10` crate 级差距（~6×）；TLS-h1 延迟门禁在干净窗口贴线越线（访问日志 ON）；OpenBSD 1 vCPU 双门禁未跑。
- 投产决策与回滚见 `OPERATOR-TODO.md`。
