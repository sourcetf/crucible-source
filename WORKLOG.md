# Crucible 工作状态（工号 1008）

> 这份文件的用途：**上下文压缩/换人之后仍能准确接着干**。
> 只写事实与可复现的命令；**不写任何凭据**（SSH 口令、GitHub token 不在仓库内）。

最后更新：2026-09-24

---

## 0. 环境与工具

| 事项 | 位置/做法 |
|---|---|
| 本地工作副本 | `C:\Users\Administrator\Desktop\crucible`（**不是**权威仓库） |
| ⚠️ 本地无法编译/检查 | 本机 rustc host 是 `x86_64-pc-windows-gnu`，但**缺 `dlltool.exe`**（无 MSYS2/LLVM）→ `getrandom`/`libloading` 等依赖编不过。**别在本地跑 `cargo check` 当作门槛**（会白等几分钟）；只能靠远程构建日志兜底。另：`cargo check … \| tail` 的退出码是 `tail` 的，恒为 0，**不能据此判断通过**（我踩过）。 |
| 权威仓库 | 远程 `/crucible`，分支 `v1.0.0-final`，推送到 `origin main`（sourcetf/crucible-source） |
| SSH 辅助脚本 | 仓库**外**：`C:\Users\Administrator\.crucible-remote\_rc.py`（执行命令）/ `_put.py`（上传）。凭据在其中 |
| 服务器 | OpenBSD 7.9，`root@83.229.125.81:22` |

**调用方式（关键）**——必须加 `MSYS_NO_PATHCONV=1`，否则 Git Bash 会把 `/crucible/...` 改写成 Windows 路径：

```bash
MSYS_NO_PATHCONV=1 python "C:/Users/Administrator/.crucible-remote/_rc.py" "<远端命令>"
MSYS_NO_PATHCONV=1 python "C:/Users/Administrator/.crucible-remote/_put.py" "C:/本地路径" /crucible/目标
```

工作流：本地改 → `_put.py` 上传 → 远端 `git commit` + `git push origin HEAD:main`。

---

## 1. 版本状态（先看这里）

- 远端 `HEAD` = **`df5c80f`** = `origin/main`
- **线上运行的二进制 = build31（09-24 13:08 构建，23m54s，0 error）**，包含到 `df5c80f`：
  build29/30 的全部内容 + **关停截止时间**（`src/main.rs`：`shutdown_timeout(3s)` + 8s 看门狗
  `exit(exit_code)`）。部署后实测：9095/8443/9081 全 200、geoip lookup/filter 回归正常、
  sync 接口回 `{"ok":true,"synced":false,"reason":"mmdb 未启用（未配置 db 路径）"}`、实例数恰 1。
- ⚠️ **改 `admin_ui.html` 后必须先跑 `python scripts/check_ui_js.py`**（构建前闸门），
  它编进二进制、编译期不检查 JS。
- ⚠️ **本地不能编译**（见 §0 表格）：本地 `cargo check` 无意义，只能靠远程构建日志。

---

## 2. 构建 / 部署 / 验证（含踩过的坑）

**构建**（`admin_ui.html` 是 `include_str!` 编进二进制的，**改 HTML 也必须重新构建**）：

```bash
cd /crucible && nohup cargo build --release \
  --features 'tls,tls_boring,go_shm_ipc,tls_nss,tls_tomcrypt' > /tmp/build.log 2>&1 &
```
耗时 9–22 分钟（有同事的 remgr 构建抢 CPU；曾被外部 SIGTERM 打断过一次）。

**部署（重要修正）**——停与起**必须是两次独立的远程调用**：
本轮实测 `sh -c 'nohup ... &'` 这种「同一条命令里停+起」的写法**也会失败**（生产因此中断约 2 分钟才手工拉回）。唯一可靠的是分两次：
1) 先只发 `pkill -f '[/]target/release/webserver.*--config'`
2) 再单独发启动命令（下面这条形式已成功过三次）：

```bash
cd /crucible && nohup /crucible/target/release/webserver --config /crucible/config.toml >> /tmp/webserver-restart.log 2>&1 & echo launched; sleep 14
```

```bash
pkill -f '[/]target/release/webserver.*--config'; sleep 2
sh -c 'nohup /crucible/target/release/webserver --config /crucible/config.toml >> /tmp/webserver-restart.log 2>&1 &'
sleep 15
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9095/
curl -s -o /dev/null -w '%{http_code}\n' -k https://127.0.0.1:8443/
curl -s -o /dev/null -w '%{http_code}\n' -u admin:admin http://127.0.0.1:9081/__admin/
```

> **坑**：`nohup ... &` 若串在 `&&` 链里、或直接跟在 `pkill` 之后，子进程会随 shell 退出而消失——已踩两次，生产短暂中断。可靠写法只有上面这种（或把停/起拆成两次独立调用）。

**确认改动是否真进了二进制**（HTML 改动可直接 grep 到标记字符串）：

```bash
grep -c tlsCiphers /crucible/target/release/webserver   # 0 表示还没编进去
grep -c navsep     /crucible/target/release/webserver
```

---

## 3. 环境硬约束

- **磁盘紧张**（`/` 常只剩 1.0–1.4G）。**验收脚本 `acceptance_test_ports.sh` 里的 `cargo test` 步骤跑不动**：它要重建 `target/debug`（≈1.5G）。跑验收前先 `df -h /`，预算 ≥2G。
- 不要动 `/root/ReMgr`（同事的项目）、`/var/swap`、`/var/turnchroot`。
- 生产实例用 `config.toml`；测试实例用 `config-test.toml` + `CRUCIBLE_DNS_STATE_ROOT=/crucible/state/dns-test`（隔离 DNS 状态，别让测试污染生产库）。
- OpenBSD 工具差异：`head` 无 `-c`；BSD grep 不支持 BRE `\|`（用 `grep -E`）；无 `date -d` / `xargs -r`。shell 是 ksh。
- 用户/同事机器上可能有并行构建（`cargo build -p remgr`），不要 `pkill` 全局的 cargo/rustc。

---

## 4. 待办（用户已确认按此顺序）

### 4.1 把"能选却让用户填"的字段改成选择式（用户明确要求：小白可用，别只留 JSON 编辑位）

**方法**：拿后端已有的校验常量逐个对回前端控件，**不要凭印象列清单**（我试过用脚本筛，启发式不可靠）。已知的固定取值集合：

| 后端常量/来源 | 对应前端字段 |
|---|---|
| `SSL_MODES`（`proxy.rs`） | 代理规则 `ssl_mode` |
| `PAGE_RULE_ACTIONS`（`page_rules`） | 页面规则 `action` |
| file_open 四个值 `auto/preview/download/execute` | 文件打开方式 |
| `/api/catalog`（返回 id/label/default_extensions） | 应用引擎 `engine` |
| access_log level：`error/warn/info/debug/trace` | 访问日志级别 |
| DNS `rtype` / zone `kind`(master/slave) | DNS 记录/分区 |

现状数据：面板已有 **19 个 `<select>`**；**8 个 `<textarea>`** 中多数是**合理的**自由文本（`tlsCert`/`tlsKey` PEM、`tomlText` 配置源码、`fileEditor` 文件内容、`accessAllow`/`accessDeny` IP 列表、`tlsCiphers`）。**`geoDnsLines` 的 JSON 文本框是主要问题，已于 `2164409` 改成表格。**

### 4.2 DNS 整体

**已有**：
- `zones` 表已有 `kind` 与 `primaries` 列
- `try_ixfr_apply`（RFC1995 分段遍历 + 序列号校验 + 失败回退 AXFR）、AXFR（无 SOA 则拒绝）、`axfr_out_acl`
- API：`/api/dns/{status,config,zones,records,modes,dnssec,axfr,override,geo,dot_doh,rootzone,test-split,geoip/*}`

**缺**：
- `.zone` 文本导入/导出（RFC1035：`$ORIGIN`/`$TTL`/相对名/括号续行/转义）
- 导入时选**增量或全量**
- **secondary/slave**：SOA 序列号轮询、refresh/retry/expire、从 primary 拉区落库
- **类 DNSPod 的记录表格**（类型/主机记录/记录值/TTL/线路 + 按类型变化的表单、搜索分页、批量添加）——现在是 JSON 编辑

### 4.3 TLS 面板体检
`enable_nss` / `enable_tomcrypt` 是遗留栈开关（真实配置项），但现在是主位、容易误导；应降级为"高级选项"，让版本/套件在前。

---

## 5. 已完成（避免重复劳动）

| commit | 内容 |
|---|---|
| `2c98ae7` | 第二轮：17 项审计缺陷（含 `parse_sni` **4 处**偏移错误、port_reuse 丢字节、file_open 在 h2/h3 未生效、Tor 死代码、UpSender 类型分裂导致连接池未接线、DoH 早于 ACL、admin 口令哈希写错用户 等） |
| `bf08be5` | 第三轮：修好自带验收闸门（BSD grep `\|` 假失败、测试配置绑生产端口 8443/853/53、明文口 port_reuse 让所有请求变 301、缺 admin 账号）+ **C 引擎 `getenv` 隐式声明截断 64 位指针导致一次 `/c/` 请求打崩整机（远程 DoS）** + geoip upsert/查询修复 |
| `9de2a09` | 第四轮记录：4 个只读审计 agent 的发现清单（含**未修项**） |
| `6850660` | 第五轮：proxy WS 升级 TE.CL 走私 / XFF 叠加 / `join_upstream` authority 拼接、`file_open` 键归一化、geoip 面板权重优先级、`line_for` 用 `or_else` 致 ASN 分线路永不命中、`zone_file_name` 撞名 |
| `579c7aa` | 第五轮记录 |
| `80b078a` | WebUI：`api()` 不再吞掉 fetch 异常（32 处调用只有 2 处 try → 面板静默失效，看起来像"按钮坏了"） |
| `a3251f7` | 清理：工作区/仓库里历轮遗留的临时产物 |
| `470e1ba` | GeoIP 离线更新实时进度（pid + `/api/geoip/update/status?since=N` 增量读日志）+ 导航按全局/站点分组 |
| `53838d3` | TLS 面板：版本 + 密码套件（**此前保存会把 `ciphers` 写死成空数组 → 点一次保存就清空已配的套件**） |
| `e0bac78` | 修上面进度接口的路由嵌套 404 |
| `2164409` | DNS 分线路改为结构化表格 |

---

## 6. 需要用户决策的安全项（未处理）

1. **管理面板在公网可达**（`http://83.229.125.81:9081/__admin/`），口令是 `config.toml` 自带的示例 `admin`（外部实测 200）。`[admin].listeners_allow` 就是用来限制暴露端口的，当前未设置。
2. Basic Auth **无失败锁定/限流**，且每次尝试都跑一次 argon2id（可作 CPU 放大）。
3. 生产 DNS 库里有历史污染分区 `verify.test`（早期测试脚本写入），清理命令记在 `contact.txt`。

---

## 7. 已复核为真、但**尚未修复**的审计发现

1. proxy 回源**全链路无超时**（connect/send/读头/读体），静默上游可长期占住连接与 64MiB 缓冲
2. `/__metrics` 在 `ip_access` + 限流**之前**返回（IP 白名单对它无效）
3. admin：`safe_join` 对不存在路径只做词法包含检查（符号链接可逃逸）；空 `listeners_allow` = 全口可达；路由用 `ends_with` 匹配（`/__adminfoo/...` 也能进管理面）；缺 `Origin` 时跳过 CSRF；鉴权前就缓冲 32MiB body
4. `connect_udp` 目标判定漏 NAT64 `64:ff9b::/96`、6to4、Teredo、CGNAT `100.64/10`
5. `ensure_sidecar` 无 per-key spawn 锁 + 超时路径丢下活着的子进程（进程泄漏）
6. geoip：`lookup_merged` 每次请求全表扫描 `ipv4`/`anycast` 且扫两遍、跑在 async worker 上；`ops.rs` filter 先 `LIMIT 5000` 再过滤（结果被静默截断）


---

## 8. 进度追加（WORKLOG 初版之后）

| commit | 内容 |
|---|---|
| `f10bcee` | **代理规则 ssl_mode=tor 保存必失败**：admin.rs 里有两份 const SSL_MODES，模块级那份（save_proxy_rules 用它校验）少了 tor，函数内副本才是全的；而前端下拉含 tor —— 面板能选、保存必 400 invalid ssl_mode。已删除函数内副本、模块级补 tor，只保留一份 |
| 本轮 | 4.1 续：TLS groups → 多选、ech_cipher_suite → 下拉、cron schedule → 带建议值的输入（datalist）。**回填时若配置里的值不在候选内，会临时补进选项**，否则整表替换保存时会把已有值丢掉 |

### 4.1 排查结论（避免重复劳动）
**本来就是选择框、无需改**：应用引擎 engine（下拉，候选来自 /api/catalog）、代理 ssl_mode（下拉）、页面规则 action（下拉）、访问日志 level（下拉）、文件打开方式（下拉）。
**已改完**：geoDnsLines（JSON 文本框 → 表格，2164409）、tlsGroups / tlsEchSuite / cronSched（本轮）。
**判断标准**：textarea 里的 PEM、TOML 源码、文件内容、IP 列表属于合理自由文本，不要动。

### 环境坑（新增，重要）
给远端传命令时**不要把带回引号/美元符的脚本内嵌在双引号里** —— 本地 bash 会先做命令替换，把 heredoc 内容搅碎（本轮已踩一次，导致提交没执行）。可靠做法：本地改好文件 → `_put.py` 上传 → 远端只放简单命令。


---

## 9. 进度追加 2：DNS 管理（4.2）

| commit | 内容 |
|---|---|
| `3e5bd85` | **.zone 导出** `GET /api/dns/zones/export?name=X`（text/plain + 附件下载，复用 gen_zone_file，导出文本与服务加载的一致）+ **类 DNSPod 记录表格**（分区下拉、一行一条记录、行内保存/删除）。路由在 admin.rs 委派给 admin_api 之前拦截，因为那条通道只产出 JSON |
| `6ae9933` | **.zone 导入**：`POST /api/dns/zones {action:import, name, text, mode}`，mode=merge 追加 / replace 先清空（新增 `del_zone_records`）。解析器 `parse_zone_text` 支持 `;` 注释（引号内不算）、括号续行、`$ORIGIN`/`$TTL`、引号 rdata 原样保留、省略 owner、可选 TTL/class、`1h/30m/2d` TTL；`$INCLUDE`/`$GENERATE` 直接报错不猜。**先全量解析再落库**，任何一行不合法整体失败并报行号。类型/名称校验复用 add_record 的同一份 `RR_TYPES`/`valid_name`（子模块可访问父模块私有项） |

**注意**：`match action` 各分支必须返回 `()`（响应在函数尾部统一回 `{"ok":true}`），所以导入条数走日志、不进响应体；前端靠刷新表格显示「共 N 条」。

### 4.2 剩余（尚未做）
- **secondary/slave 的实际行为**：`zones` 表的 `kind`/`primaries` 与 IXFR/AXFR 原语都在，缺 SOA 序列号轮询 + refresh/retry/expire 定时器 + 从 primary 拉区落库
- 分区列表现在只在点「站点状态」时刷新（`btnDnsStatus` 里挂了 `dnsRefreshZones`），未接懒加载钩子


---

## 10. 进度追加 3：secondary（从区）—— 两个阻断性 bug

用户要求支持 master/secondary。查下来发现**从区从来就不可能工作**，两个独立缺陷：

| commit |  bug |
|---|---|
| `cd07254` | named.conf 里生成的是 `primaries { 127.0.0.1;; }` —— 每个 primary 元素自带分号（`format!("{p};")`），格式化时又补了一个。named 以 `unexpected token` 拒载**整份 named.conf**（不只那一个 zone）。实测：创建从区直接返回 400 `rndc reconfig failed`。去掉多余的补分号 |
| `90046b3` | `write_all` 对**所有** zone 生成 zone 文件，包括从区。从区的文件归 named 维护（`type secondary` + AXFR/IXFR），本地写会用空记录覆盖它；而且生成的文本没有 SOA（`gen_zone_file_monotonic` 只在 `kind=="master"` 时补 SOA/NS），named 会以「不是合法 master file」拒载。已跳过非 master |

**架构要点（重要，别再重复摸索）**：本机 **BIND/named 确实在运行**（`/usr/local/sbin/named`）。master zone 由 Rust 模块从 DB 生成 zone 文件、named 提供服务；**secondary 的区传输、refresh/retry/expire 由 named 原生负责**，Rust 侧只需正确产出 `type secondary; primaries {...};` 并**不要**碰那个 zone 文件。

**遗留**：从区的记录不在 DB 里（在 named 自己那份 zone 文件里），所以面板的记录表格对从区会显示空 —— 要显示需要读盘上的从区文件。已记入待办。


---

## 11. 进度追加 4：DNS「记录不生效 / 从区起不来」的根因（`b3d7b07`）

**先记住这条**：named 的日志现在在 **`state/dns/log/named.stderr.log`**（本轮修复前它被丢进 /dev/null）。
named 用 `-g` 前台跑，而 BIND 的 `-g` 会忽略 logging 配置里的 file channel（日志里会明说
`not using config file logging statement for logging due to -g option`），所以必须靠重定向 stderr 拿日志。

**A/B 两个问题的共同根因**：`inline-signing` 让 BIND 每次签名都把 serial 往上顶
（实测 zone 文件 `1790160412` / `.signed` `1790160416`）。我们按 `now` 生成的新 serial 可能**小于**
BIND 已见过的 signed serial，于是 BIND 拒载该 zone：

```
zone X/IN (unsigned): ixfr-from-differences: new serial (1790168309) out of range [1790168310 - 3937651956]
zone X/IN (unsigned): not loaded due to errors.
```

两个表象：
1. **面板新加的记录写进了 zone 文件、服务里查不到**（zone 停留在旧内容，查询 NXDOMAIN）
2. **从区永远加载不了**：从区去主区拉 SOA 拿到 `refresh: unexpected rcode (SERVFAIL)`（因为主区自己没加载成功）

修法：写 zone 文件前把 serial 地板取为 `max(zone 文件 serial, .signed 文件 serial, DB 高水位 serial:<zone>)`，再 `+1`。

**排查手法（可复用）**：`rndc -c state/dns/etc/rndc.conf zonestatus <zone>` 看是否 loaded；
`dig @127.0.0.1 <zone> AXFR` 看实际服务内容；以及**注意 dig 的位置参数顺序** ——
`dig @server <zone> www A` 会把 `www` 当 type（我因此两次误判「查不到」，实际是查询语句写错了），
正确写法是 `dig @127.0.0.1 www.<zone> A`。


---

## 12. 进度追加 5：DNS 主区/从区全部跑通（含两次我自己的测试设计错误）

### 12.1 主区「加了记录却查不到」的根因与修法
- 现象：同一秒内「建区 + 加记录」，dig 查不到新记录；named 日志给出
  `zone X/IN (unsigned): ixfr-from-differences: new serial (…) out of range [前值+1 - …]` / `not loaded due to errors`。
- 机制：开 inline-signing 后 BIND 每次签名都会把 serial 往上顶，它的 last-seen 是这个签名后的值；
  而我们每次写完 zone 文件就把 .signed 删掉（为避免 journal out of sync），等于把唯一线索断了。
  于是「文件 serial + 1」可能仍低于 BIND 已知值 → BIND 拒载整个 zone → 记录不生效、
  从区来拉 SOA 得 SERVFAIL。隔一两秒再操作会因时间戳型 serial 自然追平而「自愈」，
  所以极难手工复现 —— 这正是它长期潜伏的原因。
- 修法（75c9e06）：write_all 里新增 named_zone_serial()，复用现成 rndc() 跑 zonestatus，
  解析 serial 与 signed serial 取较大者，作为地板参与 max(文件, DB 高水位, named) + 1。
- 验证（探针脚本，两种时序都跑）：同一秒内与隔 1.5 秒都 OK，日志无 out of range。

### 12.2 primaries 的 host:port 必须翻译（1a9e0c5）
valid_primary 允许 `192.0.2.1:53`（面板友好，还有单测断言它合法），但生成 named.conf 时是原样输出，
而 BIND 的 primaries 没有 host:port 这种写法（端口要写 `host port N`）—— 会让 named 拒载整份
named.conf，所有 zone 一起不可用（与之前 primaries 多一个分号同类的「一处格式错、全份失效」）。
新增 primary_for_named() 做翻译。实测生成的声明已是 `primaries { 127.0.0.1 port 5353; }` 且被 named 接受。

### 12.3 从区（secondary）已完整跑通
拓扑：测试实例当**主区**（config-test.toml + CRUCIBLE_DNS_STATE_ROOT 隔离，named 听 127.0.0.1:5353，
AXFR 自测通过）→ 生产实例把**同名** zone 建为 secondary，primaries 指向 127.0.0.1:5353 →
**第 166 秒**传输完成，生产 :53 能查到主区记录（203.0.113.88）。

**我在这上面错了两次，都是测试设计问题，不是产品缺陷**（记下来避免重犯）：
1. 第一次把从区建成了 `zz6-slave.example`，却让它去主区拉同名分区 —— 从区必须与主区**同名**，
   主区没有那个名字自然 SERVFAIL。
2. 等待窗口给成了 30s/180s —— BIND 对新建从区首次失败后的重试是**分钟级**，实测 166 秒才完成。

### 12.4 满盘事件（运维，重要）
磁盘曾到 **101%（可用 -18MB）**，直接后果：named 写不了 journal（日志
`managed-keys.bind.jnl: flush: disc full`）、测试实例启动卡在 half-way、从区行为异常 ——
排查时容易被误当成产品 bug。已回收约 355MB：BoringSSL 的 .o 对象文件、target/release/deps 的
*.rmeta（check 用元数据，可再生）、boringssl/bin、以及 /tmp 下我的日志。
**规则：构建前先 `df -h /` 确认 ≥1GB**（release + thin LTO 很吃盘），否则会构建失败或把生产写崩。

### 12.5 GeoIP 本轮已修 / 仍待
- 已修（6a8a3d8）：面板 lookup 每请求把 ipv4/ipv6 全表扫两遍 → 抽出 lookup_merged_with_rows
  合并为一次扫描，merge 步骤抽成 merge_pipeline 保证两个入口语义一致。
- 已修：(b) `984cdec` filter 先 ORDER BY weight LIMIT 5000 再过滤导致静默截断；
  (c) `252e983` ZZ/XX/A1/A2 被 detect_country_conflict 用未过滤值覆盖回；
  (d) `07988d6` ensure_synced 只在文件存在时跳过、force 只更新时间戳 → 现在真下载，
  且 fetch_edition 先写 .tmp 再原子改名。
- 已修（本轮，(a) 根治）：见 §13.3。ipv4/ipv6 现已带数值范围列 + 索引 + 回填 + 写入侧同步。
- **未解→已定位**：meta 表 `serial:<zone>` 高水位没落库的**真正死因**是
  `serial_from_zone_text` 只认单行 SOA，而我们自己生成的 zone 文件是**多行（括号续行）** SOA
  → 该函数恒返回 None → 高水位从未写入，`prev_serial` 退化到 `now` → 同一秒两次写入得到
  相同的 serial → BIND 认为 "zone unchanged"。`1dff5e3` 改成整段 token 扫描 + 括号容忍。
  **待 build29 部署后复验**（复验点：加一条记录后 `meta` 表应出现 `serial:<zone>` 行）。


---

## 13. 进度追加 6：WebUI 全废根因 + 两个并行修复 agent + GeoIP (a) 根治

### 13.1 WebUI「永远停在加载中」的根因（f6c3551 / ed046ee / 9753111）
`admin_ui.html` 里有 **8 处**把真实换行写进了 JS 字符串或正则字面量（本意是 `\n`）→
整个内联 `<script>` 语法错误 → 页面所有按钮失效、内容区停在加载中。
`include_str!` 把 HTML 编进二进制，**Rust 编译期完全不校验 JS**，所以构建永远是绿的。
防复发：新增 `scripts/check_ui_js.py`（纯 Python，esprima 4.0，ES2018 + 兼容 ES2019 `catch {`），
**改 HTML 后必须跑**。注意两个坑：esprima 4.0 不认 ES2019 可选 catch 绑定（已做归一化）；
无 esprima 时脚本只 WARN 不 FAIL（否则会因环境差异卡住构建）。

### 13.2 两个并行 agent 的修复（aae843e）
- **Agent B（代理/Tor）9 项**：上游三段超时（10s/30s/300s）、fail-open 的上游 URI 变成回环 SSRF、
  池键把 scheme 当 `use_tor` 传 → 跨规则复用连接、Host 头丢非默认端口、tor_socks 回环约束、
  CONNECT-UDP 漏 NAT64/6to4/Teredo/CGNAT、删掉撒谎的 `tor_client.rs`、tor_pool/NEWNYM。
- **Agent C（管理面/服务）8 项**：`/__metrics` 移到 ACL 与限流之后、admin 先鉴权再缓冲 body、
  跨站请求 403、`safe_join` 符号链接逃逸（含回归单测）、Basic Auth 按 IP 指数退避、
  rate_limit 改淘汰而非整体清空、sidecar per-key 锁 + 子进程回收、read_file 先判上限再读。

### 13.3 GeoIP (a) 根治：ipv4/ipv6 数值范围列（本轮）
**问题**：`load_from_range_table` 是 `SELECT` 全表 + 在 Rust 里逐行判定；这两张表一旦被
导入大量行，每次查询都全表扫描（而且跑在 async worker 上）。

**改法（Rust 与 Python 必须成对改，只改一侧会让新写入的行查不到）**：
| 侧 | 文件 | 改动 |
|---|---|---|
| Rust | `geoip_panel/iputil.rs` | 新增 `range_numeric_key()`：v4→u32；v6→**高 64 位**按 `hi ^ 2^63` 映射进 i64 |
| Rust | `geoip_panel/db.rs` | `create_range_table` 建表带 `start_i`/`end_i` + 老库 `ALTER` + `idx_*_numeric` |
| Rust | `geoip_panel/covering.rs` | 查询加 `WHERE start_i IS NULL OR (start_i <= ?1 AND end_i >= ?1)` |
| Python | `geoip_common.py` | `range_numeric_key()`（**按地址族分支**，不是按数值大小）+ 建表补列 + `_backfill_range_numeric` + `init_schema` 调用 |
| Python | `geoip_seed_demo.py` / `geoip_enrich_cloud_official.py` | 3 处裸 INSERT 补 `start_i`/`end_i` |

**关键设计点（别改错）**：
- IPv6 是 128 位、SQLite INTEGER 只有 64 位 → 取高 64 位并做**保序**折叠。因此
  `start_i <= key <= end_i` 只是「落在区间内」的**必要条件**（能走索引、不漏行），
  精确的 128 位判定仍由 `ipv4_in_range`/`ipv6_in_range` 在 Rust 侧兜底。
- 查询里 `start_i IS NULL` **必须放行**：未回填的老行否则会静默消失。
- Python 侧**必须按 `addr.version` 分支**。我先写成 `if v < 1<<32`（按数值大小）→
  `::`、`::1` 这类小数值 IPv6 走了 v4 分支，与 Rust 不一致 —— 验证脚本抓到了这个 bug。
- **跨语言互锁**：Rust 单测 `range_key_matches_python_literals` 里的字面量由 Python 算出，
  改任一侧都必须同步改另一侧。
- 仓库外验证脚本：`C:\Users\Administrator\.crucible-remote\_verify_range.py`
  （不依赖被测实现的独立算法比对 + 边界字面量 + 新库/老库两条路径 + 查询命中），本轮 0 FAIL。

### 13.4 磁盘（运维）
清了 `/tmp/xortest`、`/tmp/stuncheck`（我为探测 Tor/STUN 建的临时 crate，各带 260MB target）
→ 空闲由 603MB 回到 **1.1G**。
**不要删**（不是我的）：`/root/legacy-backup`、`/root/ReMgr`、`/tmp/frp*`、`/tmp/rdcheck`、`/tmp/mkhash`。

### 13.5 build29 部署与验证结果（2026-09-24，已上线）

提交 `98ed9e1` → 构建 **21m25s** 成功（0 error，106 warning 全是既有的 unused）→ 部署。

| 验证项 | 结果 |
|---|---|
| 二进制含新代码（`grep 'start_i IS NULL OR'`） | 1 ✓ |
| 生产 9095 / 8443(TLS) / 9081(admin) / geoip status | 全 200 ✓ |
| ipv4/ipv6 数值列 + 索引 + 回填（生产库） | 8 行 / 1 行，空值 0 ✓ |
| `EXPLAIN QUERY PLAN` 走 `idx_ipv4_numeric` | ✓ |
| **(b)** `filter?country=US&limit=20` 返回**整页 20 行** | ✓（修前被 CN 高权重行挤空） |
| **(c)** `lookup?ip=0.1.2.3` 顶层 country **不是 ZZ** | ✓（ZZ 只出现在 covering 原始行里，合法） |
| **(a)** range 表读路径在**活二进制**里生效 | ✓ 见下「判别探针」 |
| **(1dff5e3)** `meta` 表出现 `serial:<zone>` 高水位 | ✓ 值 1790222009 / 1790222105（两次测试递减递增正常） |
| **(1dff5e3)** 加记录后 dig 立刻查到 | ✓ 203.0.113.99 |
| h2 协商 | HTTP/2 ✓ |
| 引擎 | `/c/` `/rust/` 200；11 个引擎 200；`/jsp/` 502 = **本机没装 Java**（日志提示手工起 jsp_sidecar.sh），验收脚本同样视其为可选；`/go/` `/ruby/` `/psgi/` `/rack/` 是侧车引擎，同样 502 |

**判别探针（证明线上跑的是新读路径，别删这段方法）**：往 `ipv4` 表插一行**数值列与文本故意不一致**的记录
（文本 `203.0.113.0/24` 含目标 IP，但 `start_i=0,end_i=1` 不含）：
- 新二进制：SQL 数值预过滤把它挡在 SQL 层 → `covering` 里**不出现** ✓（实测 0）
- 旧二进制：无 WHERE 全表取回 → Rust 文本判定命中 → `covering` 里**会出现**
实测 `covering` 无该行 → 线上确为新代码 ✓（探针行测完立即删除，ipv4 行数回到 8）

**验证脚本**（仓库外 `C:\Users\Administrator\.crucible-remote\`，`.sh` 直接 `sh` 跑）：
`_verify29_prod.sh`（17 项，0 FAIL）、`_verify29_test.sh`（12 项，0 FAIL，含 DNS meta 复验）。
两个断言坑记下：①filter 也会匹配 province 等字段（DE 行带 `province=US-FL` 会命中 US），
所以断言「返回整页 N 行」而不是数 country；②ZZ 允许出现在 `covering` 原始行列表，只看**顶层** country。

**踩坑（运维）**：`pkill -f 'config-test.toml'` 会**杀掉我自己的 ssh 会话 shell** ——
它的命令行里含这个字符串。要用括号技巧：`pkill -f 'config-tes[t].toml'`。
同理 `while pgrep -f 'cargo build'` 会匹配到自己 → 死循环（我留过一个，已 kill）。

### 13.6 本轮新发现并修掉的小 bug（build30）
`POST /api/dns/geoip/sync` 返回的 `synced` 此前直接回 `run_sync`（= 是否到期/被强制），
在**没配 MaxMind license_key** 或 mmdb 未启用时，明明是空操作却回 `synced:true`
（与 07988d6 修的「面板说刚同步、数据却在老化」同类）。现在回 `synced` 真实语义
+ `reason` 说明跳过原因；无密钥时实测回 `{"ok":true,"synced":false,"reason":"未配置 MaxMind license_key"}`。
**注意**：(d) 的「真下载」因此**无法在当前配置下验证** —— 没有 license_key，
`ensure_synced` 按设计早退。要验证需要用户提供一个 MaxMind 授权密钥。

### 13.7 两个运维级发现（重要，别再被绕进去）

**① 优雅关闭没有截止时间 → 旧实例会永久残留**
`pkill`（SIGTERM）之后，进程会先关监听端口、再等存量连接收尾。实测有一个实例
（PID 71604，06:32 启动）**卡了 6 小时没退出**：fstat 显示它没有任何监听套接字，
只握着一个外部客户端的长连接（83.229.125.81:8443 <-- 49.128.218.15:56866）。
表现就是「`pgrep` 里总有 2~3 个 webserver」，但它其实**不在服务任何请求**（没有监听端口），
所以我用 `ps -p` 一看就发现它不在 `sockets` 里 —— 判断某个实例是否在服务，**看它有没有监听端口，
不要只看进程数**。
**代码层面**：SIGTERM 后应加一个强制退出截止时间（例如 10~30s 后 `exit`），否则一次部署后
旧进程可能永久残留。已记入待办，尚未修。

**② 停止生产要「升级 + 校验」，不能只发一次 pkill**
可靠序列（分两次独立调用，铁律不变）：
```
pkill -f '[/]target/release/webserver.*--config'; sleep 2; \
pkill -9 -f '[/]target/release/webserver.*--config'; sleep 1
```
然后**校验端口真空了**再启动：
```
for p in 9095 9081 8443 9445 9446; do printf '%s: ' $p; fstat -n | grep -c ":$p"; done
```
（本轮第二次部署就是这样做，生产零中断，启动后进程数恰好 1。）

**③ 已修（`df5c80f` / build31）：关停加截止时间**
`src/main.rs` 退出路径改为 `rt.shutdown_timeout(3s)` + 8s 看门狗 `exit(exit_code)`
（看门狗无条件退出，不管卡在哪）。**诚实说明：根因没能复现** —— 我构造了「CGI 现场有卡住的
请求」这个场景，新旧二进制都是 0~1s 就退出（**证伪了**「CGI 的阻塞任务会阻塞 Runtime drop」
这个猜测）。所以这条是**兜底加固**：把「可能永久不退出」变成「8s 内一定退出」，
不依赖具体是哪种机制。另外还有一个候选解释：**早先某次 stop 的 `pkill` 把自己的 ssh 会话先杀了**
（模式的字面量出现在自己的命令行里，见 §13.5 踩坑），于是那个进程根本没收到信号。

**④ 本轮顺带发现（尚未处理，记下来）**
- **CGI 引擎是串行的**：一个慢脚本（`/cgi/sleep.cgi` 睡 120s）会把整条 `/cgi/` 路径堵住，
  后续请求全部排队超时。是否是设计如此需要确认；若否，一个慢 CGI 就能拖住整个引擎。
- **CGI 子进程不在 `child_registry` 里**：关停后 `sleep 120` 那个子进程成了孤儿（自己 120s 后退出）。
  引擎子进程（fpm/sidecar）有关停回收，CGI 子进程没有。
