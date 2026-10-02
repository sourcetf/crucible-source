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

- 远端 `HEAD` = **`5bab654`** = `origin/main`
- **线上运行的二进制 = build32（09-24 13:45 构建，7m34s 增量，0 error）**，包含到 `5bab654`：
  build29/30/31 的全部内容 + **`env_lock` 空变量不再拿锁**（见 §13.8）。
  部署后实测：9095/8443/9081 全 200、geoip lookup/filter 回归正常、named 正常。
- ⚠️ **改 `admin_ui.html` 后必须先跑 `python scripts/check_ui_js.py`**（构建前闸门），
  它编进二进制、编译期不检查 JS。
- ⚠️ **本地不能编译**（见 §0 表格）：本地 `cargo check` 无意义，只能靠远程构建日志。
- 💡 只改本 crate 的代码时构建只要 **7~8 分钟**（依赖已缓存）；动到依赖才要 21~24 分钟。

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
- ~~**CGI 引擎是串行的**~~ → **已定位并修掉**，见 §13.8。
- **CGI 子进程不在 `child_registry` 里**：关停后 `sleep 120` 那个子进程成了孤儿（自己 120s 后退出）。
  引擎子进程（fpm/sidecar）有关停回收，CGI 子进程没有。修它需要把 fork 出来的 pid 从 C 引擎
  回传给 Rust（ABI 变更），影响也有限（脚本跑完即退出），暂不动。


---

## 13.8 env_lock：空 `.env` 时仍拿锁 → 同一引擎的请求被全部串行化（`5bab654` / build32）

**怎么发现的**：验证关停修复时顺手做了个并发实验 —— 起一个 `sleep 120` 的 CGI，再请求
`/cgi/`。结果**两个请求都排队到客户端超时**，而静态口 19081 毫秒级正常。

**定位**：`app_ffi::exec_dispatch` 把非内联引擎的调用包在
`env_lock::with_temp_env_named(engine, vars, …)` 里；该函数**无条件**取「按引擎」的全局锁，
并在**整个引擎调用期间持有**（因为「临时改进程环境变量」必须互斥）。可是当 `.env` 变量为空
——**默认情况**（cgi 的 docroot 里只有 deps/，没有 .env）—— 它什么都不用设却照样拿锁，
于是同一引擎（php/lua/python/perl/ruby/cgi/uwsgi/wsgi/asgi/jsp…）的所有请求退化成串行执行。

**修法**：`vars.is_empty()` → 直接 `return f()`，连锁都不碰；有变量时逻辑一字未改。

**A/B 验证（同一个脚本 `/tmp/_verify_concurrency.sh`，修复前后各跑一次）**：

| | 基线 `/cgi/` | 慢 CGI 在跑时的 `/cgi/` | 第二个慢 CGI | 静态口 |
|---|---|---|---|---|
| build31（修前） | 200 / 20ms | **超时（6s，000）** | 超时 | 200 / 1.5ms |
| build32（修后） | 200 / 24ms | **200 / 7ms** ✓ | 超时（脚本自己睡 120s，预期） | 200 / 1.1ms |

硬证据：修后 `pgrep -f 'sleep 120'` 同时有 **4 个**（多次实验并存在跑的子进程），
`/cgi/` 与 `/lua/` 都毫秒级 200 → 引擎并发恢复 ✓

**注意**：`.env` 变量**非空**时该引擎仍会被串行化（进程级 env 互斥是硬约束）。
要彻底消除得让所有引擎都走 ABI 的 `extra` JSON 传环境（目前只有内联 c/go/rust 用），属后续工作。


---

## 14. 投产前批次（用户要求「遗留全部修好、投产前不留 bug」）

### 14.1 八项待决策的默认选择（我按"安全优先"定下，可随时改）

| 项 | 选择 | 理由 |
|---|---|---|
| 规则注入响应头「追加还是替换」 | **替换**（`HeaderMap::insert`） | 配置项名就是 modify、config.rs 注释写的是 Inject/replace；追加会让同名头出现两份，客户端常取第一个 → 管理员「改了却没生效」 |
| 规则注入头是否过滤逐跳/定界头 | **过滤** | 允许注入 `Content-Length`/`Transfer-Encoding`/`Connection` 等于让配置侧凭空造定界头（响应拆分/走私面）；`Connection:` 点名的 token 一并过滤（RFC 9110 §7.6.1）。业务头（set-cookie/CSP/…）不受影响 |
| 连接池键 64 位哈希 | **取消截断，改全量字段结构体** | 池键决定「复用哪条上游连接」，哈希碰撞 = 把请求发到别的上游/别的 TLS 策略（安全问题，不只是命中率）；顺带补上漏掉的 `scheme` 与 `tor_socks` 两个出口维度 |
| Basic Auth 退避参数/持久化 | 阈值 8 次、指数退避上限 300s、**内存态**（重启即清） | 内存态足够（重启后攻击者也要重新累积）；持久化要引入存储与失效策略，收益不成比例。参数是 `FAIL_THRESHOLD`/`FAIL_WINDOW`/退避上限三个常量 |
| 状态变更请求是否强制 CSRF 特征 | **强制**（两层） | 有 Origin/Referer → 必须与本请求 Host 同源；两者都没有 → 要求 JSON content-type、`X-Crucible-Admin: 1`、或 `Sec-Fetch-Site: same-origin\|none`（浏览器跨源发这些必触发 CORS 预检，而本服务不放行跨源）。GET/HEAD 只读不拦 |
| admin 口令跑两次 argon2 | **单次 + 30s 成功备忘** | 同一请求会先过入口门（为了不收 body）再进 handle，两次哈希纯浪费；备忘只记成功凭据、键含用户表指纹，改口令/删用户立即失效 |
| `/__metrics` 是否需要口令 | **默认需要**（新增 `[admin].metrics_public`，默认 false） | 指标含内部信息；公开抓取可在配置里显式放开（仍排在 ip_access+限流之后） |
| h1 与 h2/h3 的 listeners_allow 差异 | **统一**（404 先于 401） | 谓词三协议本就相同，差异只在顺序：白名单外的口若先回 401 会弹 Basic 口令框，等于诱导凭据在未授权口上线；统一到 h2/h3 更严的那侧 |

### 14.2 同时修掉的其它遗留

- **从区（secondary）记录只读展示**：named 传输后的记录只在磁盘 zone 文件里，面板此前显示空。现在读盘解析（复用导入用的 `parse_zone_text`）并标记 `readonly`；`add_record`/`del_record` 对非 master 分区**明确拒绝**（此前会「保存成功」写进 DB 而 DNS 毫无变化 = 假成功）。面板侧：切到 DNS tab 懒加载分区列表、从区行只读并隐藏保存/删除。
- **慢 CGI 饿死整个引擎池**：`generic_pool_threads()` 是 `cpu.clamp(2,4)`，而**本机只有 1 核 → 池宽 2** ✗。两个 `sleep 120` 的 CGI 就把池占满，其它引擎的请求全部排队（验收时 lua/asp/python 被饿到客户端超时、日志里连访问行都没有）。已改为 `clamp(4,8)` 并注释理由：这些线程绝大多数时间阻塞在 I/O（等 sidecar / 等 fork 的 CGI），不是 CPU 密集。
- **`env_lock` 重写**（正文见 §13.8 后续）：锁的判据从「引擎名」改为「要装的内容」——内容相同 → 不写环境、天然并发；内容不同 → 全局互斥（进程 env 只有一个）。顺带修掉「不同引擎可同时装不同 env」（两个内嵌解释器会读到混合值）与「panic 后临时值永久留在 env 里」。
- 编译期/测试期抓到的三处：`telemetry.rs` 误用 `cfg.metrics_public`（该字段在 `AdminConfig` 上）；`basic_auth` 里一条**过期断言**（退避需累积到 FAIL_THRESHOLD，此前只记 1 次就断言已封锁——因为 `cargo test` 长期没在验收里真正跑过而没人发现）；`env_lock` 的一条单测违反了自己函数的前置条件（`matches` 要求入参已归一化）。

### 14.3 验证结果（build34 = `e1f05be`，全部实测）

| 项目 | 结果 |
|---|---|
| 单元测试 `cargo test --release` | **112 passed / 0 failed** ✓（此前 98/1） |
| 安全套件（metrics 鉴权 / CSRF 矩阵 / argon2 耗时） | **10 / 0** ✓（成功路径 96ms → 1.4ms） |
| 代理响应头（替换语义 / 逐跳+定界过滤） | **11 / 0** ✓ |
| 引擎并发（`.env` 非空时同内容并发） | **CONCURRENT_OK** ✓ |
| 从区记录只读展示 | **8 / 0** ✓ |
| 安全版验收（引擎/TLS/H3/DoT/SSLv2/geoip/DNS） | **26 / 0** ✓ |
| 生产健康 | 9095/8443/9081 全 200、metrics 401(无凭据)/200(带)、CSRF 跨站 403、geoip/named 正常 ✓ |
| 五个套件汇总 | **SUITES_PASS=5 SUITES_FAIL=0** |

### 14.4 **行为变更**（运维须知，投产前务必过一遍）

1. **`/__metrics` 默认要口令**：匿名抓取的监控端会拿到 401。二选一 —— 抓取端加 `-u`，或在 `[admin]` 里设 `metrics_public = true`（面板「Admin 暴露面」有开关）。
2. **管理面写请求需要「非简单请求」特征**：`curl -X POST` 若不带 `Content-Type: application/json` 也不带 `X-Crucible-Admin: 1`，会 403（表单型 CSRF 防护）。面板已自动带头；**手写 curl/脚本要补**。
3. **`.env` 非空时跨引擎不再并发**：项目自带 `www-apps/{c,go,php,rust}/.env`，这些引擎之间现在全局串行（正确性优先：旧实现会让两个引擎同时读到混合 env）。同引擎同内容仍然并发。
4. **规则注入的响应头是替换**：`set-cookie` 等原本可能多份的头，现在按规则值只留一份。
5. **面板对从区只读**：从区记录来自磁盘 zone 文件，不能编辑/导入（named 是唯一写入者）。

### 14.5 仍未做（有意，附理由）

- **CGI 子进程纳入 `child_registry`**：需要给 C 引擎加「fork 后把 pid 回传」的回调（ABI 变更），而判据若靠 cmdline 探测会误杀无关进程（docroot 可配成共享目录、守护化程序也带该路径）——不值得。影响也有限：CGI 引擎自己有 30s 超时 + kill+reap，孤儿只在「服务器先死」时短暂出现。
- **连接池条目永不淘汰**：键空间随规则数有界，不是无界增长。
- **`connect_upstream` 在取池之前无条件拨号**：开 `connection_pool` 时每条请求白建一条上游连接（Tor 规则白开一条电路）。修它要重排「拨号 → ALPN 选 h2 → 取池」的顺序（want_h2 依赖协商结果），改动面超出最小修复，未做。
- **admin 面板公网可达 + `config.toml` 里是示例口令 `admin`**：这是**投产前用户必须自己处理的一条** —— 改强口令 + 视情况设 `[admin].listeners_allow` 限定端口。


---

## 15. GeoIP 数据来源澄清 + 免费管线实测（用户提供原始设计文档后）

### 15.1 澄清：数据本来就是免费来源，不需要任何密钥

用户指出（并给出规格原文 §9）：GeoIP 数据来自**免费多源融合** ——
rezmoss 云厂商聚合、各云官方 geofeed（AWS/GCP/Cloudflare/OCI/Vultr/Linode）、
ipapi.is hosting 样例、gaoyifan/china-operator-ip、五大 RIR delegated、QQWry/CERNET/
ASN/Tor pool，脚本还**硬拒绝** Ip2Region / DB-IP 系 URL（`BLACKLIST_URL_PATTERNS`）。
`[dns.geo.mmdb] license_key` 那条 MaxMind 路径只是**可选补充**，不是核心数据来源 ——
我此前把「(d) 真下载无法验证」归因于缺密钥是**搞错了重点**（见 §14.3 末）。

### 15.2 面板「离线更新」真跑一遍：一次抓到 6 个失效源 + 3 个功能缺陷

按真实路径（面板按钮 → `geoip_update.sh` → fetch/merge/enrich/finish）实测，全部修掉：

**fetch 层（`scripts/geoip_fetch_layers.py`）**
| 源 | 症状 | 修法 |
|---|---|---|
| ARIN delegated（12MiB） | 传输中断 `IncompleteRead` → **整源丢失**（最大的国家基线层） | `fetch()` 加 3 次重试 + 退避；实测恢复 **80807 行** |
| GCP | v6-only 条目里 `ipv4Prefix` 缺失/null → `ipaddress` 迭代 None 抛错 | 逐条容错；实测 **1008 行**（1103 条里 95 条 v6-only 正常跳过） |
| Oracle | 老 URL 404；新地址 302（urllib 自动跟随）| 换 URL；实测 **1107 行** |
| Akamai | `ipranges.akamai.com` **已 NXDOMAIN**（域名没了） | 删除该死源（Akamai 段仍由 01-cloud 聚合覆盖，不损失覆盖） |
| ipapi.is | GitHub API 未认证**按 IP 限流**（60/h），返回 message JSON | 显式识别并报出原因；文件名匹配放宽 |
| 通用 | 上游形状漂移会让整源失败 | `write_layer` 跳过非 dict 行并计数；`cidr_row` 只接受非空字符串 |

**功能缺陷（都在面板的更新链上）**
1. **重复触发无保护** → 实测误操作拉起 **4 个并发 updater**（merge/enrich 不是为并发写的）
   → 服务端以「脚本锁目录 + 校验该 pid 命令行确实是 geoip_update.sh」判活；
   脚本侧再加 `mkdir` 原子锁（覆盖 cron/手工），锁里记 pid、进程没了自动清陈旧锁。
2. **pid 复用导致假「进行中」** → 脚本早已退出、pid 被别的进程接手 → 面板永远报
   「更新已在进行中」；同上改用「锁 + 命令行」判据（`ops::proc_is_geoip_update`）。
3. **进度 `done` 误报** → 它在「从 `since` 开始的分片」里找 `done`，`since=0` 时会命中
   好几轮之前的旧 done（更新刚起步就显示"已完成"）→ 改为读**日志尾部** 4KiB 且要求 `!running`。
4. **磁盘写满导致 merge 默默死在半路** → dmesg 刷 `file system full`，面板只看到"更新没了"、
   库里还是旧数据 → 脚本加**磁盘预检**（需 ≥ 库大小 + 256MiB，不足则跳过 merge 并给出清理建议）。

**顺带**：`geoip_tor_pool.py` 的 tor worker 是 `--RunAsDaemon` 自我守护化的，脚本退出后照跑 ——
实测一次采集后 **25 个 tor 进程残留一天**。加 `stop` 子命令，并让 `geoip_update.sh` 结束时自动停池。

### 15.3 实测结果（免费来源，全程无密钥）

| 项 | 结果 |
|---|---|
| fetch | **12/13 源成功**（唯一失败 ipapi = GitHub 按 IP 限流，报错已清晰、配额恢复即好） |
| 全链 | `geoip_update done` 正常收尾，锁被脚本自动清理 ✓ |
| 数据库 | 行数 **1,709,587 → 3,316,922**；`02-cloud-official` **5,870 → 11,740**（Google/Oracle 修复落库） |
| 与既有修复的兼容 | `start_i`/`end_i` 数值列与三个 numeric 索引**在更新后依然存在**、0 空值 ✓（更新不会破坏 §13.3 的根治）|
| 面板 | 更新期间 `running=true/done=false`；查表、filter 正常 |

### 15.4 运维须知（更新链相关）

1. **更新需要 ≈ 库大小 的空闲空间**（900MB 库 → 需 ≥1.2GB）。空间不足时脚本会**跳过 merge**
   并在日志里说明 —— 这是有意的：宁可保留上一份完整数据，也不要写坏库。
2. **可清理的缓存**（腾空间用）：`data/geoip/sources/GeoCn.jsonl`（**505MB**，由同目录
   `GeoCn.mmdb` 经 `scripts/geoip-mmdb2jsonl` 再生 ✓）、`sources/ripe.db.gz`（351MB 下载缓存，
   其对应的 `ripe.db` 本就是 0 字节 ✓）。
3. **别在更新运行中替换 `geoip_update.sh`**：bash 按文件偏移递增读取，中途改文件可能让它在
   下一个命令边界读到错位内容（本轮踩到一次，侥幸没炸）。
4. tor 池残留用 `python3 scripts/geoip_tor_pool.py stop` 收干净。

### 15.5 再补一课：判活不能只看锁（`29f5607`）

我在一轮更新**运行中**替换了 `geoip_update.sh`（见 15.4 第 3 条）→ 那轮脚本记完 `done`、
自己的 trap 也把锁清掉了，**但主进程卡住没退**。于是我的单实例判据（只看锁）放行了第二轮 ✗
→ 两轮同时写库 → 后一轮 merge 直接 `database is locked` 失败 ✗。
现在：服务端判活 = **锁 + 进程表扫描**（`pgrep -f 'geoip_update\.sh'`）双保险；
`geoip_merge.py` 的 sqlite 连接再加 `PRAGMA busy_timeout = 30000`（短暂抢锁自动等待）。

**教训**：任何"单实例锁"的实现，都要考虑「持锁者异常退出但进程仍在」这一档 ——
锁文件/锁目录只是**快路径**，最终判据要有进程层面的兜底。


---

## 16. 两处偏离规格的最终决定（用户批准按我的推荐，并允许调整实现）

用户裁决：**两处都按我推荐的来，但功能必须正常**，实现方案允许我调整。

### 16.1 引擎池宽度：`clamp(4,8)` + **给 CGI 独立窄池**

- 保留 `generic_pool_threads = cpu.clamp(4,8)`（规格写"≈ CPU clamp 2..4"）。理由：本机
  **只有 1 核** → 规格的写法只给 2 条线程，两个慢请求就能占满。
- 更关键的实现调整：**CGI 引擎改用独立池**（4 线程）。CGI 是唯一「单请求 fork 子进程、
  最长占 30s」的引擎（CGI_TIMEOUT_MS），跟通用池混在一起时几个慢脚本就能饿死
  lua/asp/python（实测过）。独立池同时把"并发 fork 数"限住 → 内存可控。
- 机制：`named_pool(engine, threads)`（键 `引擎#线程数`，rack/psgi 的串行池也走它）+
  `dedicated_pool_threads()` 决定哪些引擎要独立池（当前只有 cgi）。

### 16.2 env 锁：**保留按内容判据**（不做按引擎分锁）

- 规格写"按引擎分锁"，但那样会出现两个引擎**同时**把不同的 `.env` 装进进程环境 →
  内嵌解释器读到混合值（`php` 读 `DB=prod` 时 `lua` 读 `DB=dev` 这种情况会互相覆盖）。
  这是正确性问题，不是性能取舍，所以按内容判据（同内容并发、不同内容全局互斥）保留。
- 代价已知且可接受：**不同 `.env` 的 app 之间会串行**（项目自带样例里 c/php/go/rust 各带
  `.env`，所以这几者之间串行）。彻底两全要把 env 改走 ABI 的 `extra` 字段（规格 §7.2 本来
  就有这个字段），需要动 `libs/app-engines/**` 的 C 侧 common —— 记为后续工作。
- 空 `.env`（默认）不拿锁 ✓；同引擎同内容并发 ✓；两种都已实测。

### 16.3 GeoIP：`GeoCn.jsonl` 是**必需输入**，不是可删缓存（更正我在 §15.4 的说法）

`scripts/geoip_enrich_geocn.py` 读 `data/geoip/sources/GeoCn.jsonl`（国内主力源，实测
**220 万行**、权重 820），它由 **Go 程序** `scripts/geoip-mmdb2jsonl` 从同目录 `GeoCn.mmdb`
生成 —— **更新链不会自动生成**（且本机没装 Go：`/go/` 引擎一直 502 就是旁证）。
缺了它 enrich 只打一行 "run mmdb2jsonl first"，然后**静默丢掉最大的源**。
所以：**腾空间不要删它**（§15.4 里把它列为可删缓存是错的）；已在 `geoip_update.sh` 开工前
加显式前置检查，缺它时把后果与生成命令说清楚。

### 16.4 更新后的实测水位（供运维预算）

一轮完整更新（fetch 13/14 → merge → enrich → finish）后：库从 **943MB/443万行** 涨到
**1.27GB/574万行**；`sources/` 会重新攒下 `ripe.db.gz`（351MB，其 `ripe.db` 是 0 字节的死缓存，
可随时删）。**建议更新前留 ≥1.5GB，更新后清理 `sources/*.gz` 等死缓存**。


---

## 17. 边界清单（用户要求：每个功能、每个值的边界写清楚，用来拒绝异常请求/攻击）

以下常量与行为**都来自代码**（`grep` 可见），越界行为一栏是实际实现，不是设计意图。
改动时请同步改这张表。

### 17.1 管理面 API（`src/server/admin.rs`）——越界一律 **400 + 可读原因**

| 常量 | 值 | 约束对象 | 越界行为 |
|---|---|---|---|
| `MAX_LIST_ITEMS` | 512 | listeners/apps/rules/users/白名单等**列表条数** | 400，指出是哪一项超限 |
| `MAX_APPS_PER_LISTENER` | 64 | 单个 listener 的 `apps` 条数 | 400 |
| `MAX_APP_PATHS` | 32 | 单个 app 的 `paths` 条数 | 400 |
| `MAX_ENGINE_LEN` | 32 | `engine` 名长度 | 400 |
| `MAX_APP_WORKERS` | 128 | `workers`（应用进程/线程数） | 400（防一个配置项把机器打满） |
| `MAX_SHORT_STR` | 128 | 短字符串（用户名、枚举值、线路名等） | 400 |
| `MAX_PATH_STR` | 512 | 路径类字段（docroot/out_dir/entry 等） | 400 |
| `MAX_URL_STR` | 2048 | URL 类字段（match_url/upstream 等） | 400 |
| `MAX_HEADER_NAME_LEN` / `MAX_HEADER_VALUE_LEN` | 128 / 4096 | 规则注入的头名/头值 | 400（另：CR/LF 在构造 `HeaderName`/`HeaderValue` 时就被拒 ✓） |
| `MAX_HEADER_ITEMS` | 64 | 单条规则的注入头条数 | 400 |
| `MAX_IP_ACCESS_ITEMS` | 1024 | `ip_access.allow/deny` 条数 | 400 |
| `MAX_PASSWORD_BYTES` | 1024 | 面板设置口令的字节数 | 400（argon2id 哈希，每哈希独立盐） |
| `MAX_DNS_NAME_LEN` / `MAX_DNS_LABEL_LEN` | 253 / 63 | DNS 域名 / 单标签（按 RFC 1035） | 400 |
| 集合外的键 | — | 未知字段 | 拒（`serde` 严格解析） |

### 17.2 请求面（协议层）

| 常量/来源 | 值 | 约束 | 越界行为 |
|---|---|---|---|
| `MAX_HEADERS`（h1） | 100 | 单请求头部**条数** | 连接错误（hyper 关连接 ✗ 客户端见 400/断开） |
| `HEADER_READ_TIMEOUT`（h1） | 30s | 读完请求头的时间（slowloris ✗） | 连接超时关闭；**不影响**请求体与 keep-alive |
| hyper h1 头部总大小 | 上游默认（16KiB 量级） | 头部字节总量 | 连接错误 |
| `APP_BODY_CAP` | 32MiB | 引擎请求体 | **413** |
| `UPSTREAM_BODY_CAP` | 64MiB | 转发给上游的请求体 / admin body | **413** |
| `MAX_FULL_READ` | 16MiB | 静态文件**一次性整读**上限（200 路径） | **413 + `Accept-Ranges`**（提示改用 Range 续传） |
| `MAX_RANGE_BYTES` | 32MiB | 单个 Range 段一次返回的上限 | 收窄为 206 子段（RFC 7233 §4.1 允许），**不回 416**（否则大文件续传不可用 ✗） |
| `SMALL_FILE_MAX` / `CACHE_CAP` | 256KiB / 256 项 | 小文件内存缓存 | 超出不缓存（只影响性能） |
| 方法白名单 | — | 静态/自动索引：仅 GET/HEAD（h1/h2/h3 一致） | **405** |
| `Origin`/`Referer` 与 Host | — | 状态变更方法（POST/PUT/PATCH/DELETE） | 不同源 **403**；无来源信息时要求 JSON content-type 或 `X-Crucible-Admin: 1` 或 `Sec-Fetch-Site: same-origin\|none`，否则 **403** |

### 17.3 限流 / 认证退避 / 资源

| 常量 | 值 | 约束 | 行为 |
|---|---|---|---|
| `FAIL_THRESHOLD` / `FAIL_WINDOW` | 8 次 / 900s | 同一 IP 的 Basic Auth 失败累积 | 达阈值后**退避**（401 → 429 + `Retry-After`） |
| `MAX_BLOCK` | 300s | 退避上限 | 指数退避封顶 |
| `FAIL_TABLE_CAP` | 4096 | 退避表条目 | 满时淘汰最旧（**不整表清空** ✗ 否则攻击者刷表即可自我解封） |
| `BUCKET_CAP` / `BUCKET_EVICT_DIV` | 100000 / 64 | 限流桶 | 满时按比例淘汰最旧 |
| `POOL_CAP` | 16 | 上游连接池每键条目 | 超出不入池 |
| 引擎池宽 | `cpu.clamp(4,8)`（CGI 独立 4） | 并发引擎请求 | 队列等待；CGI 独立池使其**不再饿死**其它引擎 ✓ |
| `SYN_RATE_THRESHOLD` | 2000 | Linux syncookie 动态开关阈值 | 仅 Linux 生效（OpenBSD 走降级分支 ✓） |
| `PENDING_OPENS`（每连接） | 见 `h1.rs` | 同一连接的未完成请求 | 超出拒绝 |

### 17.4 DNS / GeoIP / 配置文件

| 项 | 边界 | 行为 |
|---|---|---|
| DNS 记录 rdata | ≤4096 字节、单行（含 CR/LF 即拒） | 400（rdata 会进 zone 文件文本 ✗ 换行=注入） |
| 分区/记录名 | RFC 1035（`valid_name`）、标签 ≤63、总长 ≤253 | 400 |
| primaries | `host` 或 `host:port` 或 `[v6]:port`，无 named.conf 元字符 | 400（生成时翻译成 BIND 的 `host port N`） |
| named.conf 面 | `listen_addr` 仅 IP/`any`/`none`/`localhost`/`localnets`；DNSSEC 算法与 key role 白名单；线路名禁保留名与重名 | 400（此前这些字段能改写整份 named.conf ✗） |
| GeoIP 导入 | 单行 rdata、解析阶段**全量校验**后才落库 | 任一行不合法 → 整体失败并报行号（不落半截 ✗） |
| 配置文件 | `cert`/`key` 必须成对；`sni_only` 需有名字；TLS 版本串白名单；root 唯一；端口非 0 且不重复 | **加载期报错**（fail-fast，不静默降级 ✗） |
| TLS 套件名 | 必须 ∈ 运行时探测出的 BoringSSL 目录（`/api/tls/ciphers` 同源） | 加载期报错并指名（此前静默剔除 ✗） |


---

## 18. 上传 + 断点续传（规格 §44）实施方案 + 剩余待办

用户指令：**做完之前不要编译**（本轮先把改动/方案攒齐）。以下为可机械执行的方案。

### 18.1 现状（已核对）

| §44 要求 | 现状 |
|---|---|
| autoindex 开关 | ✅ `autoindex.enabled/paths`（`config.rs`），目录链接按段编码 |
| `enable_upload` 开关 | ❌ 只有配置字段（`config.rs:247/296`）与面板表单回显 ✓，**无任何运行时消费者** ✗ |
| 上传端点 | ❌ 不存在（静态分支非 GET/HEAD 一律 405） |
| 断点续传（上传） | ❌ `upload_resume.rs` 74 行**零引用死代码** ✗：`resolve_dest` 把根写死 `/crucible/uploads` ✗、只查 `contains("..")` ✗、无 containment、`append()` 无并发/原子性、无临时文件与清理、未接鉴权 |
| 断点续传（下载） | ✅ h1 + h2/h3 均已支持 Range/206/416（本轮审计补齐 h2/h3 ✓）；>32MiB 单段收窄为 206 子段 ✓ |
| 4 线程并发上传 | ❌ 只有 `upload_threads` 默认 4 的配置项，无执行代码 |
| 无穿越 / 无 webshell | 读路径 ✅（`resolve_path`+containment）；写路径需按下方案实现 |

### 18.2 后端设计（`upload_resume.rs` 重写 + 端点接线）

1. **端点**：`PUT /<autoindex 路径>/<文件名>`，仅当该路径 `autoindex.enabled && enable_upload` 为真；
   同一 URL 的 `POST`/`PATCH` 亦支持（表单兼容）。非 GET/HEAD 的其它方法保持 405。
2. **鉴权**：写操作必须过 `access`（同站点的 ip_access/rate_limit）+ `file_open` 的 webshell 闸门
   （`would_execute_on_get` 为真的扩展名**拒绝上传**，除非管理员在配置里显式允许；这是 §44
   「不得有 webshell」的落地方式）。
3. **落盘**：`safe_join` 解析目标（禁 `..`/反斜杠/绝对路径/盘符，Windows 另禁 `:`）→ 临时文件
   `<name>.upload.<session>.part` 与目标**同目录**（保证 rename 原子）→ 完成后 `rename` 覆盖。
4. **断点续传语义**（`Content-Range: bytes <start>-<end>/<total|*>`）：
   - 缺 `Content-Range` → 全量写（`start=0`，先截断临时文件）；
   - 有 `Content-Range` → 校验 `start` 必须等于临时文件当前长度（否则 **409** 并回
     `X-Upload-Offset: <当前长度>`，客户端据此续传）；
   - 全部收齐（临时文件长度 == total）→ 原子 rename；否则 **202** + 当前 offset；
   - `DELETE` 同一 URL → 放弃会话并删临时文件。
5. **并发（4 线程上传）**：每目标一把 `Mutex`（`HashMap<PathBuf, Arc<Mutex<()>>>`，随会话清理），
   分片写入串行化；不同文件互不阻塞。会话 TTL（默认 1h）由维护任务清理临时文件。
6. **限额**（写进 §17 的表）：单文件 ≤ `MAX_UPLOAD_BYTES`（默认 2GiB）、单次请求体 ≤
   `APP_BODY_CAP`(32MiB)、每会话临时文件数 ≤ `MAX_UPLOAD_SESSIONS`（默认 256）。
7. **C/Go/Rust 禁用 CGI 之类的规矩不涉及此处**；不引入新依赖。

### 18.3 前端（autoindex 页面 + 面板）

- `autoindex_html`：`enable_upload` 为真时渲染「上传」按钮 + 拖放区；
- 上传器：`File.slice()` 分 4 片并发（`upload_threads` 来自配置），每片带
  `Content-Range`，逐片读回 `X-Upload-Offset` 校正；失败重试 3 次；显示总进度；
- 断点续传：刷新后按服务端回的 offset 继续（不重传已完成部分）。

### 18.4 验收标准（实现后照此实测）

1. `curl -T file http://…/up/` 全量上传成功，落盘内容与原文件 `sha256` 一致；
2. 中断后 `curl -C - -T file` 续传成功且不产生重复字节；
3. 并发 4 片上传同一文件 → 结果一致、无临时文件残留；
4. 越界：`../`、`%2e%2e%2f`、绝对路径、Windows `:`、超限文件 → 400/409/413，且**目录外无文件产生**；
5. uploads 目录里放一个 `x.php` → 请求它**不被引擎执行**（返回静态文本或 404，取决于配置）；
6. 未开 `enable_upload` 的路径 → PUT 仍 405。

### 18.5 本轮剩余待办（下一步按序，全部做完再一次性编译）

1. **上传 + 断点续传**（§18 方案）—— 最大的功能缺口；
2. `ETag`/`Last-Modified` + `If-Range`/`If-None-Match`（`static_files.rs` 6 处头构造点统一；
   解决「续传期间文件变化 → 客户端静默拼出坏文件」）;
3. 流式 body（当前 `BoxBody<Bytes, Infallible>` 只能整读缓冲 → >16MiB 单次 GET 只能 413；
   需改成可失败的流式 body）；
4. ECH 生成的配置自动进 DNS 应答（`type65_api` 目前只有面板读写，`dns/**` 无消费者）；
5. QMux（draft-ietf-quic-qmux-01）：需先取草案正文再实现，**不发明 wire format**；
6. h3/QUIC 侧限额（在 vendored `libs/quinn-boring` 里设 idle/流上限，改动面在 vendored 库）；
7. `scripts/debug_tls.sh` 仍在用 openssl CLI（辅助脚本）。

### 18.6 过程教训（血泪，务必照做）

1. **加固类改动必须用真实连接验证**：build39 里给 h1 加 `header_read_timeout` 却忘了
   `.timer()` → 每个 h1 连接 panic → 9095/9081（含管理面板）停摆约 45 分钟；**编译期毫无提示** ✗。
2. **不编译就攒代码时要格外克制**：无编译反馈时，只做小而确定的改动；中等以上改动等
   下一次编译窗口一起做。
3. **agent 会静默死亡**：本轮 2/3 个审计 agent 没交报告 ✗，其中一个在**旧文件快照**上编辑
   （本地比远端多 351 行）✗，已回滚。派 agent 时：范围要小、必须要求交清单表、
   回来先 `_cmp.py` 逐文件比对再决定接受或回滚。
4. OpenBSD 没有 `base64`（用 `python3 -m base64`）；`head -c` 不存在（用 `cut -c`）；
   `pkill` 的模式若出现在自己的命令行里会**杀掉自己的会话** ✗。


---

## 19. 上传功能进度快照（接续用，2026-09-25）

### 19.1 已完成（提交 `b931567` / `38719bf`）

| 层 | 状态 |
|---|---|
| `src/server/upload_resume.rs` | ✅ 安全会话层（同目录临时文件+原子 rename / offset 语义 → `OffsetMismatch(cur)` / 每目标会话锁支撑 4 片并发 / TTL+sweep / 2GiB、256 会话上限 / `parse_content_range`），3 个单测 |
| `src/server/upload_api.rs` | ✅ 端点逻辑（`enabled_for` 只认 `autoindex.enabled && enable_upload` + 路径前缀 / 泛型 body 流式 append / 扩展名闸门 / `safe_join` containment / 201-202-409-413-503 语义 / `x-upload-offset`），3 个单测 |
| `src/server/mod.rs` | ✅ 声明 `pub mod upload_api; pub mod upload_resume;`（**此前两者都不在模块树里** —— 所以老 `upload_resume.rs` 是游离文件、才表现为"零引用"） |
| `src/server/h1.rs` | ✅ 在 `static_files::serve` 之前 hook PUT/PATCH/POST（ACL/限速/鉴权之后） |

### 19.2 下一步（机械可执行）

1. **h2/h3 接线**：两处静态分发点是 `src/server/h2.rs:672` 与 `src/server/h3.rs:780`
   （`match static_files::serve_simple(&req, &lc).await {`）。它们返回 `Response<Bytes>`，
   而现在的 `upload_api::handle` 返回 `Response<BoxBody>` —— 所以先做**小重构**：
   * 把核心抽成 `async fn run<B>(req, lc, peer) -> (StatusCode, String, Option<u64>)`（不改逻辑）；
   * `handle<B>(...) -> Response<BoxBody>`（h1，现有签名不变）与
     `handle_bytes(req: Request<Full<Bytes>>, ...) -> Response<Bytes>`（h2/h3）两个薄包装；
   * h2/h3 各插一次同款 hook（同 h1，注意用 if-分支 return 的写法避免 req 被 move 后仍被借用）。
2. **autoindex 上传 UI**：注意 `autoindex_html(dir: &Path, url: &str)`（`static_files.rs:546`）**拿不到配置** ✗
   —— 需要改签名传入 `&AutoindexConfig`（或 `enable_upload/upload_threads` 两个值），
   并同步它的调用点（`serve`/`serve_simple` 各一处，`grep -n "autoindex_html(" static_files.rs`）。
   渲染上传按钮 +
   `File.slice()` **4 片并发**（线程数取 `autoindex.upload_threads`）+ 每片带 `Content-Range` +
   按响应的 `x-upload-offset` 校正续传 + 失败重试 3 次 + 总进度条（§18.3）。
2b. **关于"4 线程同时上传"的语义**：我们后端要求**顺序 append**（offset 必须等于已收字节数 ✓，
   这是防空洞与防覆写的关键）。因此"4 线程"的落地方式是**同时上传 4 个文件**（各自顺序分片），
   而不是同一文件的 4 片乱序并发 —— 后者需要随机写 + 已收区间位图，复杂度与出错面都大得多。
   若一定要单文件多片并发，需要把 `upload_resume` 改成 pwrite + bitmap（记录在位图上，提交前校验无洞）。
3. `ETag`/`Last-Modified` + `If-Range`/`If-None-Match`（`static_files.rs` 的 6 处头构造点统一：
   163/181/183/226/334/359/381 一带）。
4. 流式 body（解除 >16MiB 单次 GET 只能 413）。
5. ECH 配置进 DNS 应答；QMux（先取 draft 正文）；h3/QUIC 限额（vendored quinn-boring）。

### 19.3 未验证风险（build42 编译时优先看）

`upload_api.rs` 里三处 API 假设需要编译器确认：
① `admin_files::safe_join(&Path, &str) -> Result<PathBuf, E>` 的**确切签名**；
② `ListenerConfig.autoindex` 字段名与其 `enabled/enable_upload/paths` 成员；
③ `Full<Bytes>`/`Incoming` 是否满足 `Body<Data = Bytes> + Unpin + Send + 'static` 与
   `B::Error: Display`。若报错，按实际签名调整（逻辑不需要改）。


---

## 20. build42 接续手册（上传功能已写完，下一步先编译一次）

### 20.1 待编译的改动清单（都已提交、**都没进二进制**）

| 文件 | 改动 | 风险点（编译时优先看） |
|---|---|---|
| `src/server/upload_resume.rs` | 全量重写（会话层 + 3 单测） | 低；`AtomicU64` + `parking_lot::Mutex` 用法 |
| `src/server/upload_api.rs` | 新增（端点 + 3 单测） | **中**：`admin_files::safe_join(&Path,&str)` 签名、`lc.autoindex{enabled,enable_upload,paths}` 字段名、`B: Body<Data=Bytes>+Unpin+Send+'static` 与 `B::Error: Display` 是否满足（`Incoming` / `Full<Bytes>`） |
| `src/server/mod.rs` | 声明 `upload_api` / `upload_resume` | — |
| `src/server/h1.rs` | 上传 hook（静态分发前） | `req` 在 if 分支被 move、else 分支仍借用 —— 已用"分支内 return"写法 |
| `src/server/h2.rs` / `h3.rs` | 同款 hook（走 `handle_bytes`） | 同上；`req.uri().path()` 借用时机 |
| `src/server/static_files.rs` | autoindex 上传 UI（签名加 `enable_upload` + 2 调用点 + JS） | 中：`autoindex()`/`autoindex_html()` 的**所有**调用点都要带新实参（本轮改了 2 处，若有第三处会报错） |

已验证的部分（无需编译即可确认）：autoindex 里的 JS 过了 `check_ui_js.py` ✓；`r#"`/`"#` 定界符 1:1 配平 ✓；三处 hook 形态正确 ✓。

### 20.2 推荐协议（重要）

1. **先编译一次**（`cargo build --release --features 'tls,tls_boring,go_shm_ipc,tls_nss,tls_tomcrypt'`），修掉 §20.1 的"中风险"三处；
2. 然后**每条改动都走「改 → 编译 → 部署 → 真实连接验证」**（h1+h2+admin 三连 + 新端点），
   不再攒批 —— build39 的教训就是"编译过 ≠ 端口活着"（h1 Timer 事故）；
3. 上传功能的验收照 §18.4 六条（`curl -T` 全量、`curl -C -` 不重复字节、4 文件并发、
   越界 400/409/413 且目录外无文件、uploads 里的 `x.php` 不被引擎执行、未开 enable_upload 仍 405）。

### 20.3 仍未做（每条都比上传小，逐条做）

`ETag`/`Last-Modified` + `If-Range`/`If-None-Match`（`static_files.rs` 6 处头构造点：163/181/183/226/334/359/381 一带）
→ 流式 body（解除 >16MiB 单次 GET 只能 413；需把 `BoxBody<Bytes, Infallible>` 换成可失败的流式 body，牵连 h1/h2/h3 的响应类型）
→ ECH 配置进 DNS 应答（`type65_api` 目前只有面板读写，`dns/**` 无消费者）
→ QMux（draft-ietf-quic-qmux-01：先取草案正文，不发明 wire format）
→ h3/QUIC 限额（vendored `libs/quinn-boring` 里设 idle/流上限）。


---

## 21. 上传功能端到端实测：发现的两个真实缺陷（下一动作，都在这两处）

build42 部署后实测上传（测试配置 18443 已开 `enable_upload`，见 `config-test.toml` 的
`autoindex = {enabled, enable_upload, paths:["/"]}`）：`curl -k -T file https://127.0.0.1:18443/x.bin`
**挂住直到超时** ✗，且未见落盘文件。定位到两个缺陷（都不是测试问题）：

### 21.1 `Expect: 100-continue` 没有回应 → 双方互等（挂住）
curl 对较大 body 会先发 `Expect: 100-continue` 并**等服务端回 `100 Continue` 才发 body**；
`upload_api::handle` 直接 `body.frame().await` 等 body → 客户端在等 100、服务端在等 body → 卡死。
修法（二选一，推荐前者）：
* 在 `handle` 开头，若 `req.headers()` 含 `Expect: 100-continue`，**先**把 `100 Continue` 写回连接再读 body；
  hyper 1.x 的 h1 服务端需要走它暴露的接口（`hyper::server::conn::http1` 无直接 API ✗）→ 另一条更稳的路：
  在 **h1 的 `service_fn` 里**（有 `Request<Incoming>` 与连接上下文）用
  `let _ = req.extensions()` ✗ 不可行 → 实际可行方案：**用 `hyper::body::Incoming` 的
  `poll_frame` 之前先设置响应**不行（HTTP/1 的 100 必须先于最终响应发出）——
  结论：在 h1 侧用 `hyper` 的低层 `http1::Builder::serve_connection` 配合
  `http1::Connection::without_shutdown`/`into_parts` 手工发 `100 Continue`，或把上传端点
  改为**在 h2/h3 上验证**（h2/h3 无 100-continue 语义 ✗ 但 curl 在 h2 上不发 Expect ✗）。
  **先做最小验证**：`curl -H 'Expect:'`（禁用）+/或 `--http2` 走 h2 → 确认其余逻辑正确，再决定 100-continue 的实现位置。
* 同时在文档/UI 上注明：本上传端点建议客户端禁用 `Expect`（面板 JS 用 `fetch` 本就不发 ✗ 所以 UI 不受影响 ✓）。

### 21.2 无 `Content-Range` 时从不 commit（把 Content-Length 当 total）
`handle` 里 `(start, total)`：无 `Content-Range` → `(0, None)` → `Session::complete()` 恒假
→ 客户端即使发完全部 body 也只会拿到 **202**、文件永远留在 `.upload.part` ✗。
修法：无 `Content-Range` 时用 `Content-Length` 作 total（`(0, content_length)`）；
只有在**既无 Content-Range 又无 Content-Length**（分块传输）时才按"长度未知"处理（此时
收完 body 即视为完成 → 直接 commit）。
注意：`curl -T` + `-C -`（续传）会发 `Content-Range` ✓ 这条路是好的 ✓（§18.4 第 2 条要靠它）。

### 21.3 实测命令（修完照此跑）

```sh
# 1) 全量（禁用 Expect 或走 h2）→ 期望 201 且 sha256 一致
curl -k -H 'Expect:' -T /tmp/up.bin https://127.0.0.1:18443/up-test.bin
sha256 -q /tmp/up.bin; sha256 -q /crucible/www-apps/up-test.bin
# 2) .php → 403；3) ../ → 400；4) 生产口 9095 → 405
```


### 21.4 build43 实测结果（h1 全通，h2 仍挂）——下一动作

**h1（`curl -k --http1.1 -H 'Expect:' -T`）：全通 ✓**
* 3MB 全量上传 → **201 / 36ms**，尺寸 3145728 精确、**sha256 与源文件完全一致** ✓
* `.php` → **403** ✓（扩展名闸门）；生产口（未开 enable_upload）→ **405** ✓
* 分片：先发 `Content-Range: bytes 0-999999/3145728` → **202** ✓；再发偏移不符 → **409** ✓
  （断点续传的 202/409 语义正确 ✓）
* `Content-Length` 当 total 的修复（§21.2）已生效 ✓（否则不可能 201）

**`Expect: 100-continue` 不是问题** ✓：hyper 1.11.1 会自动回 100（`proto/h1/conn.rs:405-408`
“automatically sending 100 Continue”），实测禁用 Expect 与不禁用都能 201 ✓。

**新发现并已修：编码穿越被当字面文件名接受 ✗**
`PUT /..%2f..%2fetc%2fpasswd` 曾返回 **201** —— 因为路径未解码，`safe_join` 的 `..` 检查没触发，
于是 docroot 里多出一个叫 `..%2f..%2fetc%2fpasswd` 的文件（**没有逃逸**，但客户端意图是穿越、
目录留脏名字）。已在 `upload_api` 加第一道判据：**拒绝含 `%2f`/`%5c`（编码分隔符）的路径**、
以及**解码后含 `..` 段**的路径（与 static 层 `normalize_url_path` 同一套），400 拒绝。

**仍未解决：h2 路径挂住 ✗（下一步）**
`curl -k -T`（ALPN 选到 h2）**挂到客户端超时**，证据链：`/crucible/www/.up-test.bin.upload.part`
**被创建了**（说明 `safe_join` + 建临时文件都成功了 ✓）→ 卡在**读 body 的循环**里，
且 h2 流因此没有窗口推进 → 双方互等。h1 同一份代码全通 ✓，所以问题在 **h2 侧的 body 接线**：
h2 的 `Request<Bytes>` 里拿到的 body 很可能不是本次请求的完整 body（dispatch 点之前/之后
body 已被消费或仍由协议层持有）→ `handle_bytes` 把 `Bytes` 包成 `Full` 之后读到的是空流，
于是 `received=0 < total` 永不完成、也永不返回。
下一步：读 `h2.rs` 该分发点上游如何取 body（`serve_simple` 的 `Request<Bytes>` 从哪来），
把上传 hook 移到**body 已经真正收齐**的那一步之后；在此之前，**不要**给 h2/h3 开 upload
（生产本来就没开 ✓，测试配置也没在 h2/h3 上依赖它 ✓）。


### 21.5 build44 复验：h2 的 PUT 挂住**与上传无关**（预先存在的 h2 缺陷）【结论已作废 → §21.6】

移除 h2/h3 的上传 hook 之后复验（测试实例 build44b、18443 已开 enable_upload）：

| 检查 | 结果 |
|---|---|
| h1 全量上传 | **201 / 37ms**，sha256 与源一致 ✓ |
| 穿越 `..%2f..%2fetc%2fpasswd` | **400** ✓（修复生效） |
| `.php` | **403** ✓ |
| **h2 上的 PUT**（无上传代码参与） | **000 / 15s 挂住** ✗✗ |

结论：**h2 上带 body 的非 GET 请求（PUT/PATCH）会挂住连接**，与上传功能无关 ——
移除 hook 后照旧。h1 同样请求完全正常，所以缺陷在 h2 侧的 body 处理：
极可能是「非 POST 方法的请求体没人去读」→ 客户端与 h2 流互等（窗口不推进）。
**影响**：任意客户端可用 PUT 挂住一条 h2 连接（不是全站 DoS，但属可用性缺陷，
且这类连接会一直占着任务与 socket）。
**下一步**：查 `src/server/h2.rs` 里 body 的收取条件（找 `request_has_body` 之类的判定，
看是否漏了 PUT/PATCH），修好后**再**恢复上传 hook（那时 h2 才会真正可用）。


### 21.6 build45：h2 请求体窗口死锁的**真根因** + 全局 DoS 修复（§21.5 的猜测作废）

**先更正 §21.5**：那里写的「body 没人读 / 非 POST 方法漏了判定」**是错的**。真根因在
上游 h2 0.4.19 的**流控契约**上（读源码确证），共两条，第 2 条比第 1 条更严重。

**① `release_capacity` 是调用方的义务 —— 这是「>1MiB 必挂死」的原因**
`RecvStream::data()` 交出的 `Bytes` 被丢弃时 h2 **不会**自动归还接收窗口；share.rs 的
`FlowControl` 文档原文：*"the caller is expected to call `release_capacity` after dropping
data frames"*。必须 `RecvStream::flow_control().release_capacity(n)`（recv.rs:464）才把额度
还给**流级 + 连接级**窗口并（按阈值批量）排 `WINDOW_UPDATE`。
我们只读 body、从不归还 ⇒ 服务端窗口收满**初始窗口 1MiB** 后停在 0 ⇒ 对端再也发不出 DATA、
`data()` 永远 Pending ⇒ **双向互等**。阈值实测**精确落在窗口大小**上：

| body 大小 | 修复前 |
|---|---|
| 1048576 B（= 1MiB 窗口） | 立刻 405 ✓ |
| 1049600 B | 挂到客户端超时 ✗ |
| 3145728 B | 挂到客户端超时 ✗（h2/TLS 与 h2c 明文都复现） |

**② 在飞配额在 accept 循环里 await ⇒ 一条连接即可让所有 h2 连接停摆（远程可触发的 DoS）**
旧代码 `H2_INFLIGHT.acquire().await` 位于 `while let Some(..) = conn.accept().await` 循环体内、
`tokio::spawn` **之前**：await 期间 `conn` 不被 poll ⇒ **连接驱动停摆**（回应写不出、
`WINDOW_UPDATE` 发不出、该连接所有流一起卡住）。而配额是**全局** 256 ⇒ 一条恶意连接开 256 个
慢速流就能让**所有** h2 连接失去响应。改成任务内 `timeout(5s, sem.acquire_owned())`：
正常突发照旧排队（配额拿不到才 503），连接驱动永不停摆。

**顺带补的边界**（用户要求「每个功能每个值的边界写清楚」）：

| 常量 | 值 | 越界行为 |
|---|---|---|
| `H2_BODY_IDLE_TIMEOUT` | 60s（两次 `data()` 之间的空闲上限，nginx `client_body_timeout` 同语义） | **408** + 结束该流 |
| `H2_MAX_INFLIGHT` | 256（全局在飞流） | 超出 → 等待 `H2_INFLIGHT_WAIT` |
| `H2_INFLIGHT_WAIT` | 5s | 仍拿不到 → **503**（`Retry-After: 1`） |
| `REQUEST_BODY_CAP` | 8MiB（h2/h3 先收齐再处理） | **413** |
| `H2_MAX_HEADER_LIST_SIZE` | 64KiB | h2 层终止该流（ENHANCE_YOUR_CALM） |
| `H2_MAX_CONCURRENT_STREAMS` | 256（每连接） | 对端不得再开流 |

分片上传的「两次请求之间长停顿」不受 408 影响（那是空闲**请求内**读不到字节的判据）。

**改动**（`src/server/h2.rs`、`src/server/h3.rs`）
* body 循环里 `body.flow_control().release_capacity(n)` —— 真正的修复；
* 配额获取移入 spawn 的任务 + 限时 + 503（accept 循环只做 `conn.accept()`）；
* 新增 408 分支；
* **恢复 h2/h3 上传 hook**（`h2_tail`/`h3_tail` 里 `upload_api::handle_bytes`，位置与 h1 一致：
  ACL/限速/basic_auth/apps/proxy 之后、静态之前）；
* 两条源码级回归测试：body 循环必须含 `release_capacity`；accept 循环到 `tokio::spawn`
  之间不得出现 `acquire`。

**build45 实测（测试实例 18443 已开 `enable_upload`，全通）**

| 检查 | 结果 |
|---|---|
| h2 TLS+ALPN 3MB 上传 | **201 / 51ms**，sha256 与源一致 ✓（修复前 000/15s 挂死） |
| h2 1MiB+1024（窗口边界） | **201 / 25ms** ✓ |
| h2c 明文 3MB（19081 未开 upload） | **405 / 54ms** ✓（不再挂） |
| h1 3MB 回归 | 201 / 33ms，sha 一致 ✓ |
| h2 GET | 200 ✓ |
| h2 上传闸门：`..%2f..%2fetc%2fpasswd` / `x.php` | **400** / **403** ✓ |
| 同一条连接：大 body 之后再来一个请求 | 201 → **200** ✓（窗口确实归还了） |
| h2 9MB（超 8MiB 收集上限） | **413 / 105ms** ✓ |

**生产（已切 build45）实测**：9095/9081（明文 h1+h2）200 ✓；**h2 PUT 3MB → 405 / 56ms** ✓；
**h2 POST 3MB → 405 / 36ms** ✓；8443（www）、9445、9446（TLS）均 200 ✓。
生产此前同样带「h2 上任意 >1MiB body 请求挂死 + 256 慢流可致全站 h2 停摆」的活缺陷，
本轮一并修掉（这也说明之前的构建/部署没有覆盖到 h2 大 body 这条路径）。

**下一步**：h2/h3 上传仍是「先收齐再处理」⇒ 单请求上限 `REQUEST_BODY_CAP`(8MiB)；
要支持大文件得把 h2 的 `RecvStream` 包成 `http_body::Body`（每帧归还额度）直接交给
`upload_api::handle` 流式写盘（h1 已是流式，上限 `MAX_UPLOAD_BYTES`=2GiB）。


### 21.7 build46：条件请求（ETag / Last-Modified / If-* / If-Range）

**问题**：静态层完全没有验证器 —— 响应不带 `ETag`/`Last-Modified`，因此不可能有 304；
浏览器/CDN 每次都整份重传（大文件尤其贵）。`If-Range` 语义缺失更危险：续传客户端拿着
**旧验证器**请求，服务端照样给**新文件**的那一段，客户端把新旧内容拼在一起 ⇒ 静默的文件损坏。

**改动**（`src/server/static_files.rs`；h1 的 `serve_file` 与 h2/h3 的 `serve_simple` 共用同一套）
* `validators()`：`ETag = "{len:x}-{mtime_secs:x}"`（nginx 同款），`mtime` **截断到秒**
  —— HTTP 日期只有秒精度，不截断会让 `If-Modified-Since` 永远判「已修改」、304 永不出现。
* `eval_conditions()`：按 RFC 9110 §13.2.2 顺序求值 If-Match → If-Unmodified-Since →
  If-None-Match → If-Modified-Since；304 不带 body/Content-Length，412 带文案。
* `if_range_allows()`：验证器不符 / 弱标记（`W/`，强比较不成立）/ 无法解析 → **忽略 Range 回 200 全量**。
* 200 / HEAD / 206 全部带 `ETag` + `Last-Modified`。
* 依赖新增 `httpdate = "1"`（纯 Rust、无传递依赖；registry 里已有 1.0.3，不需新下载）。
* 4 个新单测：ETag 列表/弱比较/`*`、条件求值顺序与 304/412、If-Range 闸门、mtime 秒截断。

**实测（build46，测试实例）**

| 检查 | h1（18443 TLS） | h2（18443 TLS） |
|---|---|---|
| ETag / Last-Modified 存在，且两协议**完全一致** | ✓ `"1b-5e0d5da5"` | ✓ 同值 |
| `If-None-Match` 命中 → 304（body 0 字节） | ✓ | ✓ |
| `If-None-Match: *` → 304 | ✓ | — |
| `If-None-Match` 不命中 → 200 | ✓ | — |
| `If-Modified-Since` 同秒 → 304；更早 → 200 | ✓ / ✓ | ✓ |
| `If-Match` 不符 → 412；相符 → 200 | ✓ / ✓ | ✓（412） |
| `If-Unmodified-Since` 更早 → 412 | ✓ | — |
| `Range`+`If-Range` 相符 → 206(size=5)；不符 → **200 全量**；弱标记 → 200 全量；日期形式 → 206 | ✓✓✓✓ | ✓（不符→200） |
| HEAD → 200 且 body 0 字节 | ✓ | ✓ |
| 明文 h2c（19081）同样具备验证器 + 304 | ✓（ETag `"16-5e0ced25"`，304，If-Range 不符→200） | |

**诚实边界**：该 ETag 是*弱*语义（同一秒内等长改写识别不出），但按业界惯例不加 `W/` 前缀，
所以客户端会当强验证器用（也才能配合 `If-Range`）。要真正强验证器必须改成内容哈希，
意味着每个请求都要全量读文件 —— 代价与收益不成比例，故不做。


### 21.8 build47/48：>16MiB 大文件改为**流式**（此前一律 413）

**问题**：`Response<BoxBody>`（h1）与 `Response<Bytes>`（h2/h3）都把 body 放在内存里，于是
`len > MAX_FULL_READ`(16MiB) 的静态文件只能回 **413**：浏览器点一个 20MB 的文件不带 Range，
就是这条路径（等于大文件在浏览器里根本下不动）；Range 只能拿 ≤`MAX_RANGE_BYTES`(32MiB) 的分段。

**做法**：静态层改为返回「**空 body + `FileSource` 标记**（放在 response extensions）」，
由各协议的发送路径分块（64KiB）读盘：

| 协议 | 位置 | 实现 |
|---|---|---|
| h1 | `h1::stream_file()` + `handle_request` 收口点 | 后台任务读盘 → mpsc（容量 2 帧，天然背压）→ 自定义 `hyper::body::Body`；`BoxBody` 的错误类型是 `Infallible`，读失败只能结束流 + 记日志 |
| h2 | `serve_io` 发送分支 | 逐块 `send_data`（h2 流控自带背压），最后一帧 END_STREAM |
| h3 | `handle_incoming` 发送分支 | 逐块 `send_data` + `finish()`（QUIC 流控背压） |

* 用 extensions 传来源而不是改 body 类型：**不动** 30 多处 `Response<BoxBody>` 构造点。
* 访问日志在流式响应下记真实长度（否则会记 0）。
* Range 仍优先（206，≤32MiB 内存）；HEAD 仍短路（200 + Content-Length，无 body）。

**实测（build47，测试实例；20MiB 随机文件，比对 sha256）**

| 检查 | 结果 |
|---|---|
| h2 TLS 全量下载 | **200 / 20971520 字节 / 0.22s**，sha 一致 ✓ |
| h3（`curl --http3`）全量下载 | **200 / 20971520 字节 / 0.43s**，sha 一致 ✓ |
| h2c 明文全量下载 | **200 / 20971520 字节 / 0.18s**，sha 一致 ✓ |
| h2 / h3 `Range` | 206 / 1024 字节、206 / 100 字节 ✓ |
| h2 `HEAD` | 200、body 0 字节、`content-length: 20971520` ✓ |
| h2 `Range` + `If-Range` 不符 | 200 全量（20971520）✓ |
| **h1 全量下载** | build47 实测 **413**（漏改 `serve_file` 里那条 413 分支）✗ → build48 修复后 **200 / 20971520 字节 / 0.14s，sha 一致 ✓** |
| h3 条件请求 | ETag 存在、`If-None-Match` 命中 → 304 ✓ |
| h3 上传 20MB | **413**（h2/h3 单请求 8MiB 上限，见下） |

**生产（build48，8443 TLS 口，临时文件 20MiB 用完即删）**：h1 **200 / 0.16s**、h2 **200 / 0.18s**、
h3 **200 / 0.43s**，三个协议 sha256 全部一致 ✓ —— 生产此前「≥16MiB 文件一律 413、
浏览器下不动」的缺陷消失。

**已知限制（未变）**：h2/h3 的请求体仍是「先收齐再处理」⇒ 单请求 ≤ `REQUEST_BODY_CAP`(8MiB)，
超出回 413（提示改写：分片 Content-Range 或走 h1/h1 上限 2GiB）。
解掉它需要把 h2 的 `RecvStream` 包成 `http_body::Body`（每帧 `release_capacity`）并让
`upload_api::handle` 直接流式写盘 —— 那要求把 `handle_h2` 的「闸门」与「分发」拆开
（ACL/限速/basic_auth/apps/proxy 必须先于 body 消费），属于结构性改动，单独一轮做。


### 21.9 build49：ECH 配置进 DNS 应答（`[[dns.https_rr]]`）

**问题**：ECH 的发现路径**只有 DNS** —— 客户端解析公开名时拿到 `ech=` SvcParam 才会启用 ECH。
此前服务端 `ssl.ech = true` 已生成 ECHConfigList（`state/ech/ech_config_list.bin`），
但 DNS 里没有任何地方发布它 ⇒ **ECH 对客户端等于不存在**（配置"生效"了，却没人知道）。

**实现**（`src/server/dns/mod.rs`）
* `DnsConfig` 新增 `[[dns.https_rr]]`：`name`（zone 内相对名或 FQDN）/`alpn`/`port`/`ech`/
  `priority`（默认 1）/`target`（默认 `.`）。**默认空 = 零行为变化**（不写就不发布，现网应答不变）。
* `auto_https_records()` 读 `state/ech/ech_config_list.bin` —— 服务端**实际在用**的那份，
  保证「DNS 里发布的」与「TLS 上启用的」绝对是同一份（发布一份客户端解不开的配置比不发布更糟）。
* 按 zone 归属过滤（`relative_owner`：`example.com`→`@`、`www.example.com`→`www`、根区不自动发布）；
  **面板同名 HTTPS 记录优先**，自动生成只在缺失时补。
* 缺 ECH 物料时**省略** `ech=` 参数（绝不写空值 —— 空值会让客户端以为 ECH 可用却解不开）并记 warn。
* `gen_zone_file_monotonic_ext(..., extra)`：extra 行做单行/名字校验（防 zone 文件注入）。
* 3 个单测：`https_rdata` 渲染与省略、`relative_owner` 归属映射（含大小写与根区边界）。

**实测（build49 测试实例；测试态明文 DNS 口 = 5353）**

| 检查 | 结果 |
|---|---|
| 建区 `echo.test` → 5 个 view 的 zone 文件 | 全部写入 `@ 300 IN HTTPS 1 . alpn="h2,h3" port=18443 ech="AEX+DQBBAQ..."` ✓ |
| `dig @127.0.0.1 -p 5353 echo.test HTTPS` | **NOERROR / ANSWER: 1**，应答含 `ech=`（base64 内可见 public_name=crucible.local）✓ |
| 面板加同名 HTTPS 记录后 | 自动记录被面板覆盖 ✓（面板优先，符合设计） |
| 未在配置里的名字（echo2/echo3.test） | 不生成 ✓（只按配置的名字发布） |
| 生产（build49 已部署） | prod 的 named.conf 里 0 个用户 zone ⇒ 这项在生产是 no-op；h2/h3/DoH/DNS 全部照常 ✓ |

**踩坑记录**：`11853` 是 **DoT** 口，测试态明文 DNS 在 **5353**（`scripts/dns_verify.sh` 也这么取）。
我第一次用 11853 查，得到「connection timed out」，误判成 DNS 没在跑 —— 是测试脚本写错，不是服务端问题。

**要真在生产发布**：你的真实域名建好区之后，在 `[dns]` 里加（示例已放进 `config-test.toml`）：
```toml
[[dns.https_rr]]
name = "你的公开名"     # 应与 ssl.ech_public_name 一致
alpn = "h2,h3"
port = 443
ech = true
```
**边界**（与「每个值的边界写清楚」的要求对齐）：
* `dns.https_rr` 为空 → 一个字节都不写进 zone（默认行为，现网零影响）；
* `name` 不在任何已建区内 → 不发布（不报错，靠 `dig` 或 zone 文件核对）；
* `ech = true` 但无 `state/ech/ech_config_list.bin` → 省略 `ech=` 并 warn（不会写出空值）；
* 面板已有同名 `HTTPS` 记录 → 面板的赢，自动的不写（避免覆盖管理员意图）；
* `rdata` 含换行/名字非法 → 该条被丢弃并写日志（防 zone 注入）；TTL 固定 300。


### 21.10 build50：h3/QUIC 传输层显式限额（quinn 的默认值里有一条是「无上限」）

**问题**：`src/server/h3.rs` 之前直接用 `quinn::ServerConfig::new(...)`，一个传输参数都没设
⇒ 全用 quinn 0.11 的库默认值。其中一条**危险**：
`TransportConfig::default().receive_window = VarInt::MAX` —— 连接级接收窗口**无上限**。
单连接内存上界于是变成 `max_streams × stream_receive_window`
（默认 100 × 1.25MB ≈ **125MB/连接**）：攻击者开 N 条 QUIC 连接、每条开满 100 个流、
持续发数据而我们故意不读，内存就按连接数线性放大。QUIC 跑在 UDP 上、源地址可伪造，
这种放大比 TCP 侧更划算。

**改动**（`src/server/h3.rs`）：新增 `quic_transport_config()` 挂到 ServerConfig，
并打一行启动日志（限额可见、可审计）：

| 参数 | 值 | 与 quinn 默认的差别 / 理由 |
|---|---|---|
| `max_concurrent_bidi_streams` | 256 | 默认 100；与 h2 的 `H2_MAX_CONCURRENT_STREAMS` 对齐 |
| `max_concurrent_uni_streams` | 256 | 默认 100；单向流（WebTransport/QMux 方向）同样设界 |
| `max_idle_timeout` | 60s | 默认 30s；RFC 9308 §3.2 要求 ≥30s，60s 兼顾移动端抖动 |
| `keep_alive_interval` | **不设（None）** | 刻意：设了等于连接永不过期；空闲连接应被回收 |
| `stream_receive_window` | 1MiB | 默认 1.25MB；与 h2 的 `H2_INITIAL_WINDOW_SIZE` 对齐 |
| `receive_window` | **8MiB** | 默认 `VarInt::MAX`（无上限）—— **本次最关键的收紧**，单连接接收缓冲上界 |
| `send_window` | 8MiB | 显式写死（默认 8×1.25MB ≈ 10MB） |
| `datagram_receive_buffer_size` | 1MiB | 显式写死，避免由库默认决定 |
| 0-RTT | 默认关 | 上一轮已在 `quinn-boring` 修好（只有 `ssl.early_data = true` 才接受） |

**实测（build50）**
* 启动日志（测试实例与生产各一行）：`h3 quic limits: bidi=256 uni=256 idle=60s
  stream_window=1048576 conn_window=8388608 send_window=8388608 datagram_recv=1048576` ✓
* h3 20MiB **下载** 200 / 0.37s / sha 一致 ✓（8MiB 连接窗口限制的是我们**收**多少，不影响发）
* h3 串行 5 次请求 5/5 = 200 ✓；h3 分片上传 202 → 201、拼装 sha 一致 ✓
* h1/h2 20MiB 回归 200 + sha 一致 ✓
* 生产（已切 build50）：h1/h2/h3 全 200，DNS 正常 ✓

**QUIC 侧边界小结**：单连接接收缓冲 ≤ 8MiB；单流接收 ≤ 1MiB；同时在飞双向/单向流各 ≤ 256；
空闲 60s 回收（无 keep-alive）；0-RTT 默认不接受；datagram 接收 ≤ 1MiB。

**仍未做**：QMux 协议本体（`src/server/qmux.rs` 目前是「真在生效的流预算 + 诚实说明」，
协议本体需要一个新 QUIC 帧类型与 HTTP/3 上的协商，属独立一轮）；h2/h3 单请求 >8MiB 上传
（设计见 §21.8；**分片上传在 h1/h2/h3 上均已实测可用**，面板 UI 就是分片发的）。


### 21.11 build51：h2 请求体按需收齐 + 上传走流式（单请求 20MB 从 413 变 201）

**问题**：h2 此前把**每个**请求体先收齐进内存（`REQUEST_BODY_CAP` = 8MiB），
于是 >8MiB 的单请求上传一律 413；而 h1 是流式（上限 2GiB）—— 同一操作在两个协议上行为不同。

**做法**（`src/server/h2.rs`、`src/server/upload_api.rs`、`src/server/dns/dot_doh.rs`）
* 新增 `H2RecvBody`：把 h2 的 `RecvStream` 包成 `hyper::body::Body`，**逐帧归还接收窗口**
  （h2 0.4 的契约），并带 60s 空闲超时（超时即 body 读错误）。归还推迟到下一次 `poll_frame`。
* 请求体统一装箱成 `H2Body`（错误类型擦除）。`serve_io` 只做**预判**「像不像上传」：
  上传 → 保持流式；其余 → `collect_bytes(cap=8MiB)`。各分支仍按需自行收齐 ——
  所以 page_rules 改写路径 / app / proxy 抢走 URL 时最坏只是少一次流式机会，**语义不分叉**。
* `h2_tail` 分发顺序不变（apps → proxy → 上传 → 静态）；只有 apps/proxy 不接管时，
  才把流式 body 交给新的 `upload_api::handle_stream`（body 直接透传，不先收齐）。
* DoH 分支改为**只对确实是 DoH 的请求**收 body（新增 `dot_doh::is_doh_request`，
  判定条件与 `doh_prepared` 的早退分支一致）—— 否则普通上传会被白白套上 8MiB 上限。
* `collect_bytes` 的错误语义与旧行为**逐条对齐**：超限 413 / 空闲超时 408 / 读错 400。
* 回归测试：`release_capacity` 必须在 `H2RecvBody` 内且在 `poll_data` 之前；
  `h2_tail` 里 `handle_stream` 必须早于 `collect_bytes`（防止退回「先收齐」）。

**实测（build51，测试实例）**

| 检查 | 结果 |
|---|---|
| h2 单请求 **20MB** 上传 | **201 / 0.28s**，sha256 一致、无残留 `.part` ✓（此前 413） |
| h2 单请求 9MB（刚越旧上限） | **201** + sha 一致 ✓ |
| 分片上传（h2，2 片 4MiB） | 202 → 201 + sha 一致 ✓ |
| 上传闸门 | 穿越 **400** / `.php` **403** ✓ |
| DoH（h2 POST `/dns-query`） | **200** + 113 字节应答 ✓（我改过这条分支，重点回归） |
| admin API（GET/POST） | 200 / 200 / 200 ✓（admin 分支改为先收齐） |
| h2 20MB 下载 + 条件请求 | 200 + sha 一致、`If-None-Match` → **304** ✓ |
| 非上传路径的 9MB POST | **413 / 0.09s**（快速失败）+ 同连接后续 GET **200** ✓（边界不变） |

**生产（build51 已部署）**：h1/h2/h3 全 200、admin API 200 ✓。

**仍未做**：h3 侧同样的流式化（`RequestStream::split()` + 把 recv 半边包成 `http_body::Body`；
h3-quinn 自己会归还流控，主要工作是把响应发送改走 split 出来的 send 半边）。
在此之前 h3 单请求上限仍是 8MiB（h2 已无此限，h1 一直是 2GiB）。


### 21.12 build52：DoT 准入（ACL / 限速 / 并发上限）—— 之前是「谁能连 853 就白拿递归」

**问题**（审计 agent 报的第一条，我核实属实）：`run_dot` 的 accept 循环**没有任何准入** ——
无 ACL、无限速、无并发上限，accept 一次就 spawn。而 DoT 查询会被转发给 named，named 的
allow-recursion 里硬编码了 127.0.0.1（转发源）⇒ **谁能连上 853，谁就得到一个无限制的递归
解析器**：可打上游、刷缓存、当放大器（DNS 反射），且 TLS 握手成本由我们承担。
更要命的是这与 `[dns] recursion_acl`（文档写「空 = 仅本机」）的语义直接矛盾：
DoH 侧本来就排在 ip_access + 限速之后，DoT 侧却完全没有这道门。

**改动**（`src/server/dns/dot_doh.rs`、`DotCfg`）
* `[dns.dot]` 新增 `allow`（IP/CIDR 白名单）、`rate_per_sec`、`burst`、`max_conns`。
* **白名单解析**：`dot.allow` 非空用它；否则沿用 `[dns] recursion_acl`；两者都空 ⇒ **仅回环**。
  这样「公开解析器」与「仅本机」两种意图都由既有配置决定，不再出现「配置说仅本机、实际全网可用」。
* 三道准入（**判定失败直接丢连接，不做 TLS 握手**，避免白耗握手 CPU）：
  ① ACL（复用 `access::is_allowed`，含 v4-mapped v6 归一化）→ ② 单 IP 限速（复用 `rate_limit::allow`）
  → ③ 进程级并发连接上限（`Semaphore`）。
* 默认值：rate 20/s、burst 40、max_conns 128；**0 视为「用默认」**（整段 `[dns.dot]` 缺失时
  serde 会走 `DotCfg::default()` 全 0，若把 0 当「不限」就会静默变成无限制）。
* 启动日志打印生效策略，便于审计。

**实测（build52）**

| 检查 | 结果 |
|---|---|
| 启动日志（测试/生产） | `dns: DoT listening on … (allow=0.0.0.0/0, rate=20/s burst=40, max_conns=128)` ✓ |
| 测试实例 DoT 查询（源=回环，白名单命中） | 有应答 ✓（113/110 字节） |
| 生产 DoT 查询（源=回环） | **有应答**（83 字节、rcode 0、ancount 2）✓ |
| 生产 DoT 查询（源=公网 IP，非回环） | 有应答 ✓ —— 因为生产**显式**配了 `recursion_acl = 0.0.0.0/0`（公开解析器意图），
现在 DoT 与之一致（此前是"配置说仅本机、实际全网可用"的矛盾态） |
| 生产 DNS 53 / HTTP h2 | 正常 ✓ |

**运维含义**：要限制 DoT 来源就写 `[dns.dot] allow = ["10.0.0.0/8"]`（或收紧 `[dns] recursion_acl`）；
两者都不写即「仅本机」。公开提供 DoT 时，限速与并发上限现在默认生效（20/s/IP、128 连接）。


### 21.13 build53：审计报告落地（第 1 批）—— 上传闸门绕过(P0) + h3 头部/空闲 + 会话回收 + 完成判定

三个只读审计 agent 的报告已到（h3/QUIC+QMux、DNS、请求体与流控）。本批修 4 条最要命的：

**① [P0] 上传扩展名闸门可被「尾斜杠 / `/.` / 重复斜杠」绕过**（`upload_api::has_exec_ext`）
旧实现只看原始路径的**最后一个段**：`PUT /up/shell.php/`（或 `/up/shell.php/.`、`/up/shell.php//`）
让 name 变成空串 → 扩展名判成「没有」→ 闸门放行，而 `safe_join` 归一化后文件**真的写到**
`<root>/up/shell.php` ⇒ **webshell 落盘**，随后由 PHP 引擎执行。
修法：取「最后一个非空且不是 `.` 的段」再判扩展名。实测 `PUT /x.php/` → **403** ✓。

**② [P1] h3 头部区无上限 + 请求体无空闲超时**（`h3.rs`）
* `max_field_section_size` 从未设置 → h3 默认 `VarInt::MAX`(≈2^62)，而校验发生在**收齐整帧之后**：
  声明「HEADERS 帧长 4GiB」再慢慢发就能按速率 1:1 吃内存，直到分配失败（Rust 分配失败 = abort）。
  现在显式设 **64KiB**（与 h2 的 `H2_MAX_HEADER_LIST_SIZE` 对齐）。
* 请求体读取无空闲超时 → 「发完 HEADERS 不发 FIN 也不再发数据」的客户端用约 50 字节流量
  就能永久钉住一个任务 + 一个流 + 一个 QMux 名额。现在加 **60s 空闲超时**（与 h2 同语义）。

**③ [P1] `sweep_expired()` 从未被调用 → 256 个被弃会话后所有新上传恒 503**（`server/mod.rs`）
会话只能在 commit/abort 里被删，而客户端断连 / 读 body 出错 / 超限这些路径既不 commit 也不 abort
⇒ 会话与 docroot 里的 `.part` 文件都**永久残留**（磁盘无界增长；256 之后新文件名一律 503）。
现在 300s 维护循环里调用 `upload_resume::sweep_expired()` 并记日志。

**④ [P1] 完成判定把「总长未知」压成一个**（`upload_api` + `upload_resume`）
`Content-Range: bytes N-M/*`（RFC 合法写法）此前与「压根没有 Content-Range」共用 `total=None`
⇒ 首片就被判完成：**201 告知客户端传完（文件被静默截断）**，且会话被 commit，
后续分片只会收到 409 OffsetMismatch(0) —— 永远拼不回来。
现在三态分明：① `Some(n)` → 收够才完成；② 无 Content-Range → EOF 即完整；
③ `*/` → **永不在本请求里判完成**（一律 202 + X-Upload-Offset，客户端须用带具体 total 的请求收尾，
这是 RFC 语义下唯一正确的读法）。
顺带修掉 `complete()` 里的 `t > 0`：空文件（`Content-Length: 0` / `bytes 0-0/0`）此前永远 202、
目标文件永不生成。

**⑤（顺带）`enabled_for` 的前缀匹配补上路径边界**：配置 `paths = ["/up"]` 不再把
`/uploads/...`、`/upfoo/...` 当成上传目录（与 `AutoindexConfig::allows` 同一套判定）。

**实测**：见本节末（build53 部署后补）。

**实测（build54，测试实例 18443 已开 enable_upload）**

| 检查 | 结果 |
|---|---|
| P0 闸门：`PUT /x.php/`、`/x.php/.`、`/x.php//`、`/x.php` | **全部 403**，docroot 里**没有**落盘 ✓（修前 3 种绕过写法都会 201 并写出 webshell） |
| `Content-Range: bytes 0-1023/*` 首片 | **202** ✓（不再 201 静默截断） |
| 收尾片（`bytes 1024-2047/2048`） | **201**，拼装 sha256 一致 ✓ |
| 空文件（`--data-binary ''`） | **201** + 0 字节落盘 ✓（修前永远 202） |
| 常规 3MB 上传 h1 / h2 / h3 | **201 / 201 / 201**，三个协议 sha256 全一致 ✓ |
| h3 100KB 头部 | **431**（被拒），随后正常请求仍 200 ✓ —— 服务器不崩、不无界吃内存 |
| h2 100KB 头部 | 连接被 h2 层终止（000），随后正常请求仍 200 ✓ |

**交付过程中自己踩到并修掉的 bug（诚实记录）**：build53 里我的完成判定用了**会话**的 total
（会话的 total 是首次创建时定的，用 `*/` 开的会话恒为 None），于是「首片 `*/` → 收尾片给具体 total」
仍然回 202 ✗。build54 改为用**本次请求**声明的 total，并在客户端给出具体 total 时清除
`wildcard_total` 标记 —— 复验 202 → 201 + sha 一致 ✓。
（教训：状态放在会话里、判定却要看请求，是这类「看起来差不多」的 bug 的常见来源。）

**生产（build54 已部署）**：h1/h2/h3 全 200、DNS 正常；生产未开 enable_upload，
`PUT /x.php/` → 405（闸门不参与，符合预期）。

**下一批（报告里还没落地的）**：DNS 侧 3 条 P1（RPZ/answers 的 SOA serial 单调性、
zone 导入按字节切下标的 panic、RPZ value 按类型校验）、h3 侧 2 条 P2（CONNECT-UDP 绕过预算、
`fec0::/10` 准入）、上传侧 2 条 P2（并发同名会话互写、在途 `.part` 可被下载）。


### 21.14 审计第 2/3 批：h3 预算与 v6 准入、zone 导入 panic、`.part` 泄露、DNS serial 与值校验

**① [P2] CONNECT-UDP 完全绕过 QMux 预算**（`h3.rs`）：预算是在 CONNECT 分支 `return`
**之后**才取的 ⇒ 隧道不受闸门约束：单连接可开 256 个隧道 = 256 个 UDP fd + 256 个任务，
连接数无上限。现在预算在 CONNECT 之前获取（RAII 守卫持有到隧道结束）。

**② [P2] CONNECT-UDP 目标准入漏 `fec0::/10`**（`connect_udp.rs`）：`is_unique_local()` 只覆盖
`fc00::/7`、`is_unicast_link_local()` 只覆盖 `fe80::/10`，于是 RFC 3879 的 site-local
（部分环境仍按此路由）被当「公网单播」放行 —— 与 v4 侧拒绝 `10/8`、`192.168/16` 的口径不一致。
已加位判定（`o[0]==0xfe && (o[1]&0xc0)==0xc0`）。

**③ [P1] zone 导入按字节切下标 → NBSP 必 panic**（`dns/admin_api.rs::zone_tokens`）：
旧实现 `b[i] as char` 把 UTF-8 字节当 Latin-1 码位，而 `U+00A0`(NBSP)/`U+0085`(NEL) 的
`is_whitespace()` 为真 ⇒ token 的 end 落在多字节字符**中间**，调用方 `&logical[a..b]` 立刻
panic（"byte index N is not a char boundary"）。触发只需一个 NBSP（浏览器/Word 粘贴 zone
文件极常见），**从区（AXFR）内容也走同一解析器**。改为 `char_indices` 迭代。
实测：含 NBSP 的 zone 导入 → 200，服务存活 ✓。

**④ [P2] 在途 `.part` 可被下载**（`static_files.rs::resolve_path`）：
`.{目标名}.upload.part` 与目标名一一对应且可猜 ⇒ 任何客户端可 `GET /.secret.pdf.upload.part`
读走别人正在上传（或已中断）的内容 —— 正是最可能含敏感数据的那份。现在直接拒绝该模式。
实测：直接 GET 与 `%2e` 编码形式都是 **404**，普通文件仍 200 ✓。

**⑤ [P1] RPZ/answers 的 SOA serial 无单调性兜底**（`dns/mod.rs`）：用户 zone 早就做了四层地板，
RPZ/answers 却是裸 `chrono_now()` ⇒ 同秒两次编辑产生同一个 serial，而 BIND 只在 serial
**更大**时重载 ⇒「加一条 override → 面板 ok → 服务里还是旧规则」。现在两个生成器都从
**已落盘旧文件**读回上一个 serial 取 `max(now, prev+1)`（新增 `next_serial`/`read_zone_serial`）。
实测：同秒内三次 override → answers 区 serial **1790391945 → 946 → 947 严格递增** ✓。

**⑥ [P1] RPZ value 未按类型校验**（`dns/mod.rs`）：answers 区是**一个文件**，任何一行非法都会让
named 拒载整个区；而 RPZ 的 a/aaaa/txt 规则全部 CNAME 指向该区 ⇒ 一条空值/坏 IP 让
**全部 override 静默失效**（面板仍 ok）。现在 A/AAAA 必须是合法 IP、TXT 非空、CNAME 必须是
合法域名，且**在写盘前** 400 拒绝。实测：空 A / 坏 AAAA / 空 TXT 全部 400 且 answers 区零坏记录，
合法 override 仍生效（`dig s1.test A` → NOERROR + `192.0.2.11`）✓。

### 21.15 上传：同名并发会话不再互相截断/混写

**问题**（审计 P2）：会话按**目标路径**共享，而「从 0 全量重传」会截断临时文件并把 `received`
归零。两个客户端同时上传同名文件时：A 正在逐帧写 → B 从 0 重传截断了文件并归零 →
A 下一帧用 `sess.received()` 取 offset 继续追加 ⇒ 两段数据混在一个文件里、`received` 是两者之和、
`complete()` 可能提前成立 ⇒ **双方都可能拿到 201，文件是损坏的**（浏览器超时重传、或任何并发写同名文件的客户端都会触发）。

**做法**：`session_for` 里「start == 0 且旧会话 `received > 0`」时，只有当旧会话**已静默**
（`RESET_IDLE_GRACE` = 30s 无触碰）才允许截断重来；否则回 **409 + X-Upload-Offset: 当前值**。
这样既挡住并发混写，又给「断线后重试」留了活路（客户端可据 409 里的偏移续传，或 30s 后重来）。










### 21.16 build73/74：Tor 全链路（入站 HS 接线 + 出站 5 缺陷 + 自愈/关停）—— 双向真实 200 验证

**起因**：`检查tor相关的功能是否完整实现`。查出来的不是「缺一点」，而是**两半都没真正跑起来**：
出站反代曾在 `connect_upstream_inner` 里无条件 `bail!("tor upstream not supported")`（于是 `via_tor` /
`ssl_mode=tor` / `rule.tor_socks` 三个配置项全是死代码）；入站 `spawn_from_config` **全树零调用点**
（`mod.rs` 里只有一句 "tor_hs removed" 的注释，而模块明明在）⇒ 配 `[tor_hs] enabled = true`
什么都不会发生，也不报错。两处的修复与证据分列如下。

**① 出站 SOCKS5（`proxy.rs`，commit 142cbb1）**
- 应答**版本字节**未校验（只看 REP）：非 SOCKS5 服务端会被当成握手成功，后续把它的响应体当隧道数据读；
- UDS 桥 `socks5_unix_bridge` 只 `accept()` 一次且不看对端：同机任何进程都能抢先占掉那条回环连接
  （实测端口被抢则隧道接到别人身上）⇒ 改为循环 accept + 只收 peer 端口等于本连接 `local_addr().port()` 的那条；
- 默认 UDS 探测链**不存在**（文档却写着「内置优先链」）⇒ 补 `state/tor-client/socks.sock`、
  `/run/tor/socks`、`/var/run/tor/socks`、`/run/tor/socks.sock`（`stat` 判定 socket 再连）；
- config 文档里的「arti」是**从来没实现过**的承诺 ⇒ 文档与实现对齐（不做 arti：会带进第二套 TLS 栈）；
- 新增 15 条测试（用 `tokio::io::duplex` 造假 SOCKS5 服务端，覆盖 ATYP 成功 ×3 / REP≠0 /
  坏版本 / 握手拒绝 / 未知 ATYP / host 过长 / 回环强制 / 尾点 .onion 必须走 Tor / UDS 候选覆盖）。

**② 入站 HS（`tor_hs.rs`）—— 接线之后才暴露的一串问题**
- `state_dir()` 是全仓库唯一**相对** state 路径 ⇒ cwd 漂移会把 HS 密钥写错地方；改为 `current_dir()` 绝对化；
- **tor 硬要求 `HiddenServiceDir` 是 0700**：0755 时 tor 直接
  `Failed to parse/validate config: Failed to configure rendezvous options` 退出（实测），现在建目录即 chmod 0700；
- **幂等 ≠ 存活**（最要命的一条）：旧逻辑只要 `hostname` 文件在就「复用已有 HS」直接返回，**从不检查
  tor 进程还在不在、torrc 是否已与配置不一致**。实测证据：把 `ports` 从 `[[8080,28080]]` 改成
  `[[80,28080]]` 后重启服务 —— 日志照样打「复用已有 HS」，磁盘 torrc 仍是 8080，tor 进程还是上一次那个
  （`ps -o lstart` 未变），而客户端访问 `http://<onion>/` 拿到的是 tor 的
  `No virtual port mapping exists for port 80`。现在复用必须同时满足「进程在（pidfile + `ps` 核对命令行）
  + torrc 与配置逐字节一致」，否则停旧起新（密钥在磁盘上，.onion 名不变）；
- **tor 日志无处可看**：`--RunAsDaemon` 之后 stdout 被丢弃，torrc 里又没有 `Log`，于是
  `data/notice.log` 是**空的**（tor 默认 notice→stdout，而 stdout 没了）。现在 torrc 显式
  `Log notice file state/tor-hs/notice.log`，且失败时按 stderr/stdout → notice.log 的顺序取回 tor 原话；
- **关停留孤儿**：tor 是 `--RunAsDaemon` 的独立进程，不在 `child_registry` 里 ⇒ webserver 退出后
  .onion 仍可解析、连进去必然是死的。现在退出路径显式停掉「pidfile + ps 核对过」的那一份；
- **巡检自愈**（原来没有任何东西看管 tor，进程一死就静默不可达）：每 60s 调一次幂等的 `ensure_hs`，
  且**每轮读实时配置**（否则热重载后巡检会拿旧快照把 tor 改回旧配置）；
- `ensure_hs` 加进程内锁：启动/热重载/巡检三处并发时会同时判定「不在跑」各起一个 tor，第二个必因
  DataDirectory 锁失败；
- `enabled` 由 true 改 false 时**真的把 tor 停掉**（否则面板显示「未启用」而 .onion 继续对外服务）；
- 状态端点补 `running`/`pid`/`user` 三个字段：只有 hostname 会让面板显示一个「看起来正常」实则不可达的地址；
- 新增可选 `[tor_hs].user`（如 `_tor`）：启动前把 `state/tor-hs` 整棵树 chown 给该用户并把 `User` 写进 torrc
  （tor 解析完配置即降权，root 独占目录会让它启动失败）；不配时以 webserver 身份运行，并在 root 下
  **一次性**提示建议降权（tor 自己那条告警只落在 notice.log 里，面板看不到）。

**实测（build73/74，全部走真实 Tor 网络，非单测模拟）**
- 单测 **196/196**（191 + 新增 5 条 torrc/复用判据/pid 防护/user 校验）；
- 客户端 tor（独立 torrc，`SocksPort 127.0.0.1:19050`）`curl --socks5-hostname` 直取
  `.onion/index.html` → **HTTP 200**，正文 `<h1>crucible-onion-e2e-ok</h1>`；
- **出站端到端**：请求本机 `28081/o/index.html` → 反代经 tor SOCKS5 → .onion → HS → `127.0.0.1:28080`
  → 同一台服务器 → **HTTP 200 + 同一 marker**（双向在一条链里同时验到）；
- 负向对照：`ssl_mode=verify` + 明文上游 → **502** `boring TLS connect ... [WRONG_VERSION_NUMBER]`
  （verify 档没有被静默降级成明文）；
- 热重载：改 `ports` → 日志「重启 tor —— torrc 与当前配置不一致（改了 ports / user 等）」，
  torrc 出现两行 `HiddenServicePort`，tor pid 由 86385 → 45087；
- 巡检：`kill` 掉 tor → `/api/tor/status` 立刻报 `"running":false` → **20s 内自动拉起**
  （日志「重启 tor —— tor 进程不在」）；
- `enabled=false`（热重载）→ 日志「enabled 变成 false → 停止 tor」→ 状态端点 `enabled:false, running:false`；
- SIGTERM 关停 → 无孤儿 tor（`OK_no_orphan`）。

**踩坑（写进这里省得下次再踩）**
1. `HiddenServiceDir` 必须 **0700**；0755 的错误信息是「Failed to configure rendezvous options」，与权限二字无关；
2. `--RunAsDaemon` 会让 stdout 作废 ⇒ 不显式写 `Log` 文件就等于没有日志；
3. `.onion` 上访客用的是**虚拟端口**：只映射 8080 就必须 `http://<onion>:8080/`，
   `No virtual port mapping exists for port 80` 是**配置**问题而非服务故障（面板已就地提示）；
4. `ps -o args=` 在 OpenBSD 上按终端宽度截断（实测 80 列）⇒ pid 复用防护按「首词是 tor 且命令行含我们的
   torrc 路径」判断，不能整串比较；
5. 两个 listener 不能共用同一个 `root`（校验器会拦：「duplicate listener root」），e2e 测试配置要分开 docroot。

**补遗（同轮真机验证发现的第二个真 bug）：Tor 的连接预算是固定的 10s，冷电路必然误报 502**

`proxy.rs` 里 connect 阶段只有一个 10s deadline，常量注释还写着「Tor 建路在数秒量级，
10s 留了 20 倍以上余量」—— 这句话是**错的**：tor 的 SOCKS5 **应答**要等电路建好（必要时
还要先取一次新的网络共识）才返回。实测证据链：

1. 新起的 tor（UDS SOCKS，刚 bootstrap）+ 我们的反代取 `icanhazip.com` →
   `proxy error: upstream connect timed out after 10s` → 502；
2. 同一目标改走 curl + tor 的 **TCP SocksPort** 对照：冷 2.27s、热 0.97s（目标本身没问题）；
3. 我们的反代改取 `check.torproject.org`（同一台 tor）连打 6 次：1.19s / 0.80s / 0.56s ×4
   —— UDS 桥本身正确（debug 日志每次都是「使用默认 UDS /crucible/state/tor-client/socks.sock」）。

结论：**冷电路上的第一次请求**会吃掉 10s 预算，表现为周期性 502（尤其刚重启/刚部署后）。
修法：Tor 走单独的 `UPSTREAM_CONNECT_TIMEOUT_TOR = 45s`（直连仍是 10s），超时信息里也点明
「经 Tor：冷电路建路可能较慢」；新增单测 `tor_gets_a_larger_connect_budget` 防回退，
并用「accept 但永不回话的假 SOCKS 端口」真机验证：请求 45s 后 502、错误文本写明 45s（改前是 10s）。

### 21.17 审计批次（3 个并行 agent × 19 项findings）：21 处缺陷修复 + 真机复验

**做法**：三个只读审计 agent 分别扫 `proxy+onion_ca`、`static+upload+admin-files`、
`TLS+ECH+DNS`。报告里凡是我能核实的都核实了（对着代码逐条看，能上真机的一律上真机），
**核实即修**；无法核实或属于运维策略的**如实列出未修原因**（见文末）。

#### 一、最严重：上传端点的 webshell 闸门（P0）

分发（h1/h2/h3）用**原始** URL 路径问 `apps::would_handle`，落盘用 `safe_join` 的**归一化**
路径 —— 两者对 `/./cgi/pwn`、`//cgi/pwn` 结论不同：分发认为「不归引擎」→ 交给上传器，
文件却写进 CGI 引擎的 docroot，随后 `GET /cgi/pwn` 由引擎执行。
`has_exec_ext` 只看最后一段的扩展名，`pwn` 没有扩展名 ⇒ 拦不住。
**一条不带扩展名的 PUT 换一个 webshell**。修法：上传前用与 admin 文件写入**同一套归一化**
判据 `would_execute_on_get`（内部走 `web_path_of`），归一化后仍在引擎路径上就 403。

#### 二、隐藏文件泄露（P1，且**实测生产口匿名可读**）

基线证据（改前）：
```
GET /rust/.env  -> 200 (21B, text/plain)     GET /c/.env -> 200
GET /php/init.sh -> 200 (application/x-sh)   GET /php/.env -> 403（php 路由另有规则挡下）
```
access log 的 handler 显示 `/rust/.env`、`/c/.env` 是 **`app`**（引擎）吐出来的，不是静态层 ——
因为 `Path::extension(".env")` 是 `None`（前导点算主干），`ext` 成空串，于是
`extensions = ["rs", ""]` 与「无 extensions 的 catch-all」都把 `.env` 认成自己的。
而这些 `.env` 正是 `deps.rs` 读进**引擎进程环境变量**的 `KEY=VAL`。

三处一起修（缺一处就漏）：
1. `apps::match_app_indexed` / 新增 `route_owns_path`：**隐藏段不归任何引擎**（`.well-known` 例外）；
2. `static_files::resolve_path`：**隐藏路径不服务**（`.well-known` 例外，且同目录下的
   `.well-known/.secret` 仍拒 —— 例外只覆盖 `/.well-known` 这一层）；
3. `upload_api`：隐藏路径不得作为**上传目标**（`.env`、`.git/hooks/pre-commit`）。

另有「引擎被 `enabled=false` 关掉后脚本源码被当静态文件下载」（`GET /php/index.php` 直接
给源码）：`engine_owns` 现在同时问 `route_owns_path`（不看 enabled）—— 引擎开关是**服务**的
开关，不该变成「源码公开」的开关。

#### 三、代理/回源（10 处）

| 缺陷 | 后果 | 修法 |
|---|---|---|
| `would_proxy` 无边界，`try_proxy` 有边界 | `/apidocs` 被 502；手写 `path=""` **整站 502** | 三协议统一用 `path_matches_proxy_prefix` |
| `join_upstream` 拒绝含 `@` 的 rest | `/api/users/@me`、`?u=a@b` 一律 502 | 去掉该检查（authority 由「补 `/`」关死） |
| 上游 `Content-Length` 原样透传，body 却是重建的 | **响应走私**（客户端/缓存按谎报长度读下一条） | 与重建体不符即丢弃（HEAD 例外） |
| `modify_request_headers` 可注入 Host/CL/逐跳头 | 两个 Host、body 静默截断、绕过逐跳头剥离 | 与响应侧对称的过滤 |
| 客户端 XFF 被当作链首 | 后端按「取第一个」时来源 IP 可伪造 | 只写我们自己看到的对端 |
| 502 正文 `{e:#}` | 泄露上游地址、tor socket 路径、TLS 后端错误 | 固定 `502 Bad Gateway` + 本地 warn |
| 显式 `upstream_http_version="h2"` 时**不发 ALPN** | 该配置对着普通 h2 上游**永远连不上** | ALPN 三态（H2Only/Off/Auto） |
| `.onion.`（尾点）原样发进 SOCKS5 | tor 按普通域名解析 ⇒ 连不上 | 发之前去尾点+小写 |
| WS 握手读头不跳 1xx | `Expect: 100-continue` 场景硬 502 | 跳 1xx 继续读最终头 |
| `poll_read` 在 `remaining()==0` 时 `put_slice` | 潜在 panic | 提前返回 |

#### 四、onion_ca（.onion 回源**唯一**的认证手段）

* `ssl_mode = "tor"` 被映射成 `NoVerify` —— 它只是「强制走 Tor」的开关，却顺手关掉了
  「证书即公钥」校验；改为 `Verify`。
* SPKI 提取不核对算法、密钥长了就「取最后 32 字节」（对 RSA 是模数尾巴+指数、对 P-256 是 Y
  坐标 ⇒ 比的根本不是公钥），walk 失败还回退到「整份证书扫 BIT STRING」——而期望值是**公开的**
  （就从 .onion 地址解出来），攻击者可把它塞进任意位置骗过校验。现在：核对 Ed25519 OID、
  长度必须**恰好** 32 字节、**删除回退**（fail-closed）。

#### 五、其它

* admin 前缀加段边界（`/__adminX/api/files` 曾能进管理分发，`admin.rs` 内部是后缀匹配）；
* `[ip_access]` 空串配置期拒绝（运行期空串=匹配所有 ⇒ `deny=[""]` 全站 403）；
* 上传错误不回显文件系统路径；目标是目录时拒绝并让临时文件留在目标父目录（此前 `PUT /`
  会把 `.www.upload.part` 写到 docroot **之外**）；
* TLS 握手失败日志：由 ERROR + 完整 Debug（含**整个 ClientHello 字节**，实测 2KB/条、占日志
  67%，**任何匿名客户端**发一次明文 GET 就能写 ⇒ 远程日志洪泛）改为 WARN + 折叠字节数组 +
  头尾各留 180 字（保住 boring 写在末尾的 `reason: "HTTP_REQUEST"` 之类结论），完整原文降级 debug。

#### 六、验证（全部真机）

* 单测 **208/208**；
* 生产：`/rust/.env`、`/c/.env` **200 → 404**；`/rust/index.rs` 仍 200（引擎照常执行）；
  `/__adminX/api/files` → 404 而 `/__admin/api/*` → 200；`.well-known/acme-challenge/<token>`
  → 200（ACME 不受影响）而同目录隐藏名 → 404；h1/h2/**h3(QUIC)** 全 200、DNS 递归正常；
* 代理边界真机：规则 `path="/api"` 时 `/apidocs/x` → **404**（改前 502），`/api`、`/api/` → 502；
* TLS 日志真机：明文探测 8443 现在新增 **~500B/WARN**（改前 ~2KB/ERROR），且结论可读。

#### 七、有意未修（知情选择，非遗漏）

1. **上传体量预算 / 每 IP 限额**：生产**未启用上传**（所有 listener 都没有 `enable_upload`），
   而限额设计需要取舍（全局字节数？每 IP 会话数？拒绝时要不要保留已收字节？），不在本批动。
2. **app docroot 里「非隐藏、非引擎所属」的文件**（如 `/php/init.sh` 部署脚本仍 200）：这是
   运维放置策略问题 —— 建议把脚本移出 docroot，或用 `file_open` 标注；默认全拒会误伤正常的
   静态资源（css/js/png 也在同一目录）。
3. **未启用 `tls_boring` 的构建**下 rustls 回源不做 CertificateVerify：本部署启用 boring，
   该分支未触发（记录在案，避免下次有人以为「已经全路径校验」）。
4. **行尾**：本批用 Python 文本模式改文件，把 10 个文件误转成 CRLF（Windows 默认行为），
   已还原为 LF 再上传。**教训**：改文件的脚本一律用 `open(p,'wb')` 或 `newline=''`。

### 21.18 三项遗留补齐：上传体量/每 IP 预算、应用 docroot 私密文件、rustls 握手验签

§21.17 末尾列的「有意未修」三项，本轮按用户要求补齐（提交见 c 系列后续）。

#### 一、上传的体量与端点预算（此前只有「单文件 2GiB」「全局 256 会话」两个孤立上限）

**问题**：两个上限是**逐个**计量的，乘起来是 512GiB —— 而机器磁盘只有几十 GB，一个匿名客户端
就能把盘写满（本项目历史上真被写满过一次）。另外 `autoindex.upload_threads` 是**死配置**
（面板能改、写进 config、运行时无人读），以及 `session_for` 把 `peer` 参数**丢掉**（`_peer`），
于是「每 IP 限额」根本无从做起。

**做法**（`upload_resume.rs`）：
* 全局在飞预算 `MAX_INFLIGHT_BYTES`（= 单文件上限，2GiB）：会话创建时按**声明的 total 预留**，
  写入时按实际字节累计；两处都记账（`reserved` 与 `inflight`）。
* 每来源 IP 并发会话上限 `MAX_SESSIONS_PER_IP = 16`（`session_for` 现在收 `peer`）。
* **磁盘余量闸门**（`statvfs`，下限 `MIN_FREE_BYTES = 512MiB`）：创建与每次写入都要过。
  新增 507 `Insufficient Storage` 与对应文案。
* `upload_threads`：**这条当时并没有实现**（我在 §21.18 里写成了「已实现」，属于不实陈述，
  见 §21.21 的勘误与补做 —— 教训：文档里写「已实现」前必须 grep 到调用点）。
* 顺手修一个**潜在死锁**：`session_for`（先 `SESSIONS` 再会话锁）与 `commit`/`abort`
  （先会话锁再 `SESSIONS`）锁序相反，同目标名「一个在 commit、一个在做 start=0 重传」可触发
  AB/BA；现在统一为 `SESSIONS → 会话锁 → BUDGET`。

**两个 bug 是被我自己写的单测抓出来的**（值得记一笔）：
1. 第一版只「检查」声明总量却不记账 ⇒ 预留形同虚设（测试里第 33 个 64MiB 会话没被拒）；
2. `statvfs(目标路径)` 对**还不存在**的新文件直接 ENOENT ⇒ 磁盘闸门从来没生效；
   改为沿父目录上溯到最近存在的祖先。第二个尤其阴：不做断言的话它永远不会报错，
   只是「以为有闸门」。

#### 二、应用 docroot 里的运维/私密文件（`GET /php/init.sh` 此前 200）

**问题**：引擎只「拥有」自己声明的扩展名（`/php` 是 `["php",""]`），`init.sh` 既不是 php 也
不是隐藏文件 ⇒ 静态层照常服务（实测 `200 application/x-sh`，部署脚本原文）。同类还有
`*.sql`/`*.ini`/`*.log`/`*.pem`/`Makefile`/`Cargo.toml` 等。

**做法**：`static_files::app_private_path` —— 判据是「**落在应用路由前缀下** + **引擎不拥有它**
+ 命中私密扩展名/文件名」，命中就 404（`file_open = preview/download` 仍可显式放行）。
**只在这个范围内拒绝**是有意的：站点自己的 `backup.sql`（不在应用目录里）照常可分享，
而应用目录里的密钥/脚本不该被顺手端出去。

**真机**：`/php/init.sh`、`/php/Makefile` 由 200 → **404**；`/php/index.php`、`/rust/index.rs`
仍 200（引擎照常执行）、`/c/` 仍 200。

#### 三、rustls 回源的握手验签（`HandshakeSignatureValid::assertion()` 桩）

**问题**：`tls_rustls` 路径下两个 verifier（`AcceptAll` 与 onion 那个）的
`verify_tls1{2,3}_signature` 都是 `assertion()` —— **握手签名一律不验**。在 `.onion` 的 `verify`
档下，攻击者拿着目标隐藏服务的**公开**证书（SPKI 本来就来自 .onion 地址）即可原样重放、
无需私钥 ⇒「证书即公钥」形同虚设。

**做法**：改为真实验签 —— `rustls::crypto::verify_tls1{2,3}_signature(msg, cert, dss, algs)`，
算法集合取已安装的 crypto provider（`CryptoProvider::get_default()`，退回 ring 默认）。
API 形状对着 vendored 的 rustls 0.23.43 源码核对过（0.23 收 `&WebPkiSupportedAlgorithms`，
不是 0.22 那种切片；`WebPkiSupportedAlgorithms` 是 `Clone` 非 `Copy`）。

**诚实的验证边界**：这条改动**没有被编译验证过**，因为 `tls_rustls` 而**不带** `tls_boring`
的配置在本仓库**根本编译不过** —— 实测 `cargo check --no-default-features --features
'tls,tls_rustls,go_shm_ipc'` 报 **50 个既有错误**（`boring_path.rs`/`ocsp_fetcher.rs`/
`rustls_path.rs`/`cipher_catalog.rs`/`sync.rs` 等处的 `boring::` 引用没有 cfg 门）。
也就是说：这个「rustls 回退」不仅是未验证，而是**当前不可构建**（本部署启用 boring，不受影响）。
要么另开一轮把这些站点 cfg 门补齐（工作量不小），要么在文档里去掉「rustls 可作回退」的说法。
本轮先保证：**桩换成真校验**，且与 rustls 0.23.43 的 API 完全对齐（逐行核对源码）。

#### 四、验证汇总（全部真机）

| 项 | 结果 |
|---|---|
| P0：`PUT /./cgi2/pwn`（`--path-as-is`，h1） | **403**，磁盘无文件，`GET` 404（不可执行） |
| P0：同上走 **h2** | **403**（两个协议都堵住） |
| 折叠写法 `//cgi2/pwn2`、`/%2e/cgi2/pwn3` | **403**，无落盘 |
| 非应用前缀的可执行扩展名 `PUT /x.php` | 403（扩展名闸门） |
| 隐藏目标 `PUT /.env`、`PUT /cgi2/.env` | 403 |
| 正常上传 `PUT /fine.txt` | **201**（未误伤） |
| 每 IP 会话上限 | s1..s16 → 202，**s17/s18 → 503** |
| `upload_threads` 并发闸门 | §21.18 **未实现**（勘误见 §21.21）；§21.21 补做并真机验证 |
| 引擎仍执行 `GET /cgi2/index.cgi` | **200** + `cgi-ok` |
| 应用目录私密文件（生产） | `/php/init.sh`、`/php/Makefile` → **404**；`/php/index.php`、`/rust/index.rs` → 200 |
| 单测 | **212**（新增：P0 机制回归、每 IP 上限、声明量预留、磁盘余量、折叠路径不回退） |

**踩坑记录（下次直接用）**
1. **测 `PUT /./x` 必须 `curl --path-as-is`**：普通 curl 会把 `/./` 归一化掉，日志里看到的是
   `/cgi2/pwn` —— 第一轮验证因此误判成「引擎拦下了」，其实压根没发出去那个路径。
2. 磁盘闸门用 `statvfs` 时**必须沿父目录上溯**：上传目标还不存在，直接 statvfs 会 ENOENT。
3. 预算类改动一定要写「断言被拒」的单测：只写正向用例，两条 bug（不记账、闸门不生效）
   都会静默通过。

### 21.19 修好 `tls_rustls`（不带 boring）配置：从「编译不过」到 195/195 测试全绿

§21.18 里我留了一条诚实的边界：「rustls 回源的握手验签**没有被编译验证**，因为该配置在本仓库
根本编译不过（实测 40+ 错误）」。本轮把它修掉了 —— 顺带把那句「rustls 可作回退」从**空话**变回
**事实**，也让 §21.18 的验签改动拿到了编译验证。

#### 原因（都是同一类：BoringSSL 专属模块被**无条件**编译）

| 模块 | 为什么不能无条件编译 | 处理 |
|---|---|---|
| `tls/boring_path.rs` | 全文是 boring 类型（acceptor/SslStream/ECH/OCSP 装订） | `#[cfg(feature = "tls_boring")]` 整模块门控 |
| `ocsp_fetcher.rs` | `StapleSlot` 用 boring 的 X509/hash 类型，唯一调用方是 boring_path | 同上 |
| `dns/dot_doh.rs` 的 `run_dot` | `tokio_boring::accept` + `boring::ssl::SslAcceptor` | 与调用点（本就 cfg 分叉）同一门控 |
| `tls/cipher_catalog.rs` `probe()` | `SslContextBuilder` 探套件 | 只门控函数体：非 boring 构建返回**空表**，语义是「探测不可用 ⇒ 不武断拒绝」（原有注释即此意） |
| `ech_auto.rs` 的 `generate`/`raw_x25519` | X25519 keygen 走 boring `PKey` | 只门控这两处；非 boring 构建下 `generate` 给出明确报错（不是静默失败） |
| `live_config.rs` 的 `clear_acceptor_cache()` | 函数在被门控的模块里 | `#[cfg(feature = "tls_boring")]` 调用点 |
| `tls::active_stack` / `legacy_modules` | 定义在 boring_path 里，但**只用 `cfg!` 宏** | 移到 `tls/mod.rs`（两种配置共用一份实现，避免复制粘贴出两份漂移的文案） |
| 4 个测试 | 断言 BoringSSL 行为（探测/PSK 表/ECH 装载） | 与它们依赖的能力同一门控 |

#### 验证

* `cargo check --no-default-features --features 'tls,tls_rustls,go_shm_ipc'` → **CHECK_EXIT=0**（此前 40+ 错误）
* 该配置的**完整测试套件**：`cargo test --release --no-default-features --features 'tls,tls_rustls,go_shm_ipc' --bin webserver`
  → **195 passed / 0 failed**（比 boring 配置少 17 个 —— 那些是 BoringSSL 专属用例，已被正确地
  cfg 门控掉，而不是失败）
* boring 配置（生产用）：**212 passed / 0 failed**，行为不变

#### 顺手修的两件事（都是本轮自己踩出来的）

1. **磁盘被我自己顶到 102%**：`cargo test` **忘了 `--release`** ⇒ 生成 1.7G `target/debug` 产物，
   `/` 从 1.4G 余量变成 **-364M**（写盘开始失败）。`rm -rf crucible/target/debug` 后恢复 1.4G。
   生产未受影响（当场复验 h1/h2/h3 全 200）。**教训：这台机器上跑测试一律 `--release`**，
   辅助脚本已改并在注释里写明原因。
2. **5 个上传用例变得依赖环境**：§21.18 新加的磁盘余量闸门（`MIN_FREE_BYTES = 512MiB`）在盘紧时
   会正确地拒绝一切会话 —— 于是那 5 个「真落盘」用例集体失败。这不是被测对象的 bug，而是
   **用例把环境当常量**。现在：环境不足时跳过并打印原因；磁盘闸门那条用例改成**自洽断言**
   （拿 `free_bytes()` 的实测值与闸门结论比对），不再硬编码「小文件一定放得进」。

### 21.20 部署面收尾：开机自启（rc.local）+ 日志轮转（daily.local，copytruncate）

补上两处**生产环境**的缺口（不是代码 bug，是「机器一重启站点就没了」「日志没有上限」）。

#### 缺口一：没有开机自启

生产实例一直是**手工 nohup 起的**：`/etc/rc.local` 不存在、`/etc/rc.conf.local` 没有条目、
`/etc/rc.d/` 里也没有这个服务 ⇒ 机器一重启，站点与 DNS 控制面就停在那儿等人上去手工拉。

做法：`scripts/deploy/rc.local`（安装到 `/etc/rc.local`，OpenBSD 启动时执行）。要点：
* `cd /crucible` 必须在最前 —— `state/` 下的相对路径（tor_hs、dns、ech_auto）以 cwd 为基准；
* **幂等**：先判「是否已在跑」。这里踩了一次坑：第一版用
  `pgrep -f '/crucible/bin/webserver --config ...'` 判活，而当时那个实例是
  **`./bin/webserver`（相对路径）**起的 ⇒ **漏判，真的起了第二个实例**（它抢不到 853/9095
  端口，自己退出了，没造成事故，但很危险）。现在改成两步判定：`pgrep -x webserver`
  只匹配**可执行名**（`ksh -c '… webserver …'` 这类包装、名字里带 webserver 的进程都不会
  命中），再用 `ps -o args=` 核对配置路径（相对/绝对两种启动方式都能认）。
* 本机没有 `daemon(8)`，所以是 nohup 版；要变成 rc.d 服务得先给 webserver 自己写 pidfile（另说）。

#### 缺口二：日志没有轮转

之前查过 `newsyslog`：它的轮转语义是 **rename + 给进程发信号重开文件**，而
(a) 本机没有 `daemon(8)`（没法用它接管 stdout 并支持 SIGHUP 重开）、
(b) webserver 是前台进程、由 nohup 承接 stdout，**不会**重开日志文件。
于是加 newsyslog 条目反而有害：rename 之后进程继续往旧 inode 写，新文件永远是空的，
`Z` 压缩还会去压一个正在被写的 inode（日志静默丢失/损坏）。

做法：`scripts/deploy/daily.local`（安装到 `/etc/daily.local`，`/etc/daily` 每日 01:30 由 cron 调用）
= **copytruncate**：`cp -p $LOG $LOG.0 && : > $LOG && gzip -f $LOG.0`。inode 不变 ⇒ 进程的 fd
一直有效；代价是 cp 与截断之间理论上可能丢几行（访问日志可接受，而且这台机器磁盘长期紧张，
必须有个上限）。阈值 2MB、保留 7 代（可用 `CRUCIBLE_LOG`/`CRUCIBLE_ROT_MAX`/`CRUCIBLE_ROT_KEEP`
覆盖，便于验证与运维调整）。

#### 验证（全部真机）

| 项 | 结果 |
|---|---|
| rc.local 幂等（生产在跑时执行） | 打印 `already running`，`pgrep -x webserver` 仍为 1（没有第二个实例） |
| rc.local **启动路径**（停→同一次调用内执行） | `started pid 24114`，`pgrep -x webserver`=1，h1=200 |
| 「假命中」对照 | `ksh -c '… webserver --config /crucible/config.toml --help'` 不会被 `pgrep -x` 认成实例 |
| 小日志不轮转 | 真实日志 245KB（< 2MB）⇒ 不动 ✓ |
| 轮转代数与内容 | 临时日志连续轮转：`.0/.1/.2.gz` 各 3072 字节原文、主文件截为 0、`KEEP=3` 时第 4 代被丢弃 ✓ |
| **copytruncate 不变量** | 对**真实日志**轮转后发一次请求：新行写进（已截断的）`crucible-restart.log`，归档 `.0.gz` 里是轮转前内容 ⇒ 进程 fd 未失效 ✓ |
| `/etc/daily` 计划 | root crontab `30 1 * * * /bin/sh /etc/daily` ✓ |
| 生产终检 | `bin/webserver` 与构建产物 md5 一致、实例数 1、h1 9095/9081 + h2 + h3 全 200、DNS 正常、`/php/init.sh`=404、`/php/index.php`=200、`/api/tor/status`=200 |

**诚实说明**：真正的「重启机器」路径**没有实测**（不能为验证去重启生产机）。已验证的是
rc.local 的幂等与启动两条路径 + `/etc/rc.local` 是 OpenBSD 标准启动钩子（`/etc/rc` 会执行它）。
两份钩子都收进了 `scripts/deploy/`（含安装命令与上面这些理由），便于复核与重建。

### 21.21 勘误 + 补做：`upload_threads` 并发闸门（§21.18 里我把「没做的」写成了「已做」）

**勘误**。§21.18 的改动清单里我写了「`upload_threads` 变成真闸门：按 listener 端口缓存一个
`Semaphore`，拿不到许可直接 503 —— 面板上改这个值现在真的会改变并发上限」。
**这是不实陈述**：本轮 grep 才发现 `upload_threads` 只出现在 `config.rs`（字段/默认值）与
`admin.rs`（面板校验）里，**没有任何运行期调用点** —— 我写文档时把「打算做/以为做了」写成了
「已做」。已把 §21.18 那一行改成勘误指引（保留原文可追溯，不静默改写历史）。

**补做**（`upload_api.rs`）：
* 新增 `upload_gate(port, threads)`：按 listener 端口缓存一个 `tokio::sync::Semaphore`，
  尺寸取自该 listener 的 `autoindex.upload_threads`（clamp 1..=16）；热重载改了值就**换新的**
  semaphore（旧的在飞请求继续持旧 permit，退出自然释放）。
* `handle()` 进来先 `try_acquire_owned()`：拿不到立刻 **503 + `Retry-After: 1`**，
  文案写明 limit（`上传并发已满（limit=N，可在面板调整 autoindex.upload_threads）`），
  并发一条 `warn` 日志（含 listener 端口、limit、peer）。permit 活到函数返回 ——
  覆盖整段 body 读取与落盘。
* 为什么是「立刻 503」而不是排队：排队会把连接与 body 缓冲堆在内存里，正好是闸门要防的东西。

**真机验证**（测试实例 :28097，`upload_threads = 2`）：

| 项 | 结果 |
|---|---|
| 顺序上传 3 次 | 201 / 201 / 201（不该拦的没拦） |
| 6 个并发慢上传（`--limit-rate 40k`，512KB） | **恰 2 个 201**（conc2/conc6）+ **4 个 503**（conc1/3/4/5） |
| 503 响应 | `retry-after: 1` + 正文写明 `limit=2` ✓ |
| 闸门释放后 | 顺序上传仍 **201** ✓ |
| 服务端日志 | 4 条 `upload: 并发已满（listener :28097，upload_threads=2）peer=…` ✓ |
| 落盘 | 成功的那两个文件内容完整（512KB）✓ |

**教训（已写进流程）**：文档里写「已实现」之前，必须 `grep` 到**调用点**（字段被解析/被校验
不等于被使用）。这类「假实现」比缺功能更糟：它让后续的人（包括我自己）不再去看那段代码。

**顺带踩坑**：验证脚本里用了 `wait` 等 6 个后台 curl —— 结果它**把同脚本里 nohup 起的服务端
也一起等了**（`wait` 等所有子进程），脚本挂住。清理后手动补完了 ③–⑥ 的检查。

### 21.22 两处「声称已做但没真机验过」的补验 —— 顺带挖出一个**宿主机配置**问题

上一轮我在 §21.16/§21.18 里写过 `[tor_hs].user` 降权与「磁盘余量闸门」，但都没真机跑过。
本轮补验，两条都不虚 —— 其中一条**当时根本跑不通**。

#### 一、`[tor_hs].user = "_tor"`：代码没问题，是宿主机 `/dev/null` 坏了

补验结果：tor 退出码 1、onion 生成不出来，`ps` 里根本没有 tor 进程；但目录属主已经正确
chown 成 `_tor`（`drwx------ _tor _tor`）。查日志发现真因是 tor 自己写的：
```
[err] /dev/null can't be opened. Exiting.
```
`ls -la /dev/null` → **`crw-r--r--`（0644）** —— 而 `/dev/null` **必须是 0666**（POSIX：任何进程
都要能写它）。tor 在 `--RunAsDaemon` 之后会 fork 并把 stdin/stdout/stderr 指向 `/dev/null`，
于是降权到 `_tor` 之后这一 open 失败、直接退出。同机 `/dev/zero` 是正常的 0666，说明某次
`MAKEDEV`/手工操作把 `/dev/null` 改成了 0644（时间戳已不可考）。
**这不是我们的代码问题，但它会让「任何」降权运行的守护进程挂掉**（不只是 tor）。

处理：`chmod 666 /dev/null`，随后同一个测试实例重跑：
* tor 进程属主 = **`_tor`**（`ps -o user=` 实测）
* `state/tor-hs`、`hs`、`data` 全部 `drwx------ _tor _tor`
* onion 正常生成（`b5orj6y3…onion`），`/api/tor/status` → `running:true, pid:91288, user:"_tor"`

**运维须知**：`chmod 666 /dev/null` 已生效且重启后仍在（OpenBSD 的 /dev 是静态节点目录），
但如果哪天重跑 `MAKEDEV` 或重新安装系统，**要复查 `/dev/null` 的权限**（本机曾是非标准的 0644）。

#### 二、磁盘余量闸门：以前只有单测，现在真机触发过

闸门本身（§21.18）此前只有单测覆盖 —— 无法在不填满磁盘的前提下让它生效。为此加了一个
**运维/验证用**的环境变量 `CRUCIBLE_MIN_FREE_BYTES`（覆盖 `MIN_FREE_BYTES`，默认不变）：
运维可以把小磁盘机器的余量下限调高，验证时可以调到「必然触发」。

真机：`CRUCIBLE_MIN_FREE_BYTES=2000000000`（2GB > 本机 1.3G 余量）起测试实例 →
`PUT` 上传回 **507**（`服务端存储余量不足（在飞上传总量或磁盘余量触及上限）`）、
**磁盘上没有任何文件**；把阈值调回默认重启 → 同一个 PUT 回 **201**、落盘 4096 字节。
这条闸门现在是真的接在落盘路径上，而不只是「一个没人调用的判据」。

#### 三、顺带修掉一个我自己的**错误上报缺陷**（就是上面那次故障暴露的）

`--RunAsDaemon` 之后 tor 的**致命错误常常只写进它自己的 `notice.log`**，而我们捕获的
stderr/stdout 里只剩启动 notice。旧 `tor_said()` 的实现是「stderr/stdout 全空才去读
notice.log」——于是它把唯一的原因（`[err] /dev/null can't be opened`）**漏掉了**，
报出来的是一串「Tor can't help you if you use it wrong」的噪音（我第一次排查时就是靠手工
cat notice.log 才找到原因）。现在：两处都读，按 **`[err]` → `[warn]` → 其它** 排序，
各取最近几条，致命行排最前。

**这个修复的排序逻辑第一版是错的**（末尾统一 `reverse()` 把优先级翻掉了：`[err]` 行虽然出现
却排在 notice 后面），被我同时加的单测 `tor_said_prioritizes_fatal_lines_from_notice_log`
抓住 —— 那个用例的数据形状就来自这次真机故障。修好后 **213/213 通过**。

### 21.23 DNS 落盘改为**原子写**（rename）：不再有「半截 named.conf / 半截 zone」的窗口

三个 agent 的 DNS 审计一直没回报，我自己把这块过了一遍。查到的第一个真问题是**落盘语义**：

`named.conf` / 各 zone 文件 / `root.zone` 占位 / RPZ / answers / `rndc.conf` / `session.key`
此前**全部**是 `std::fs::write` —— 也就是**原地截断再写**。本项目有明确的历史证据说明进程会
非正常终止（日志里反复出现 `shutdown: 8s 内未能正常退出 → 强制 exit(1)`、worklog 里记过
OOM 与满盘），而这类文件写到一半被杀/断电的后果是：

* `named.conf` 半截 ⇒ **named 起不来 ⇒ 整个 DNS 全挂**（还有 `named.conf` 里的 rndc 密钥）；
* zone 文件半截 ⇒ named 拒载该区（`not loaded due to errors`）⇒ 该区 SERVFAIL，
  而面板上一切显示正常。

修法：新增 `write_atomic(path, data, mode, owner)` —— 写**同目录**临时文件 → 设权限/属主 →
`rename(2)` 覆盖。同文件系统内 rename 是原子的，named 只会看到旧文件或新文件。
**权限/属主必须在 rename 之前设**：否则 rename 到 chmod 之间会出现「新 named.conf 是 umask
权限」的窗口（0640 → 短暂 0644，里面有 rndc 密钥）。全部 8 处（含 DNSSEC 密钥上传）已改。

真机验证（部署后即触发：启动时 `dns::startup → reconcile → write_all` 会重写全部文件）：

| 项 | 结果 |
|---|---|
| DNS 仍正常 | `dig @127.0.0.1 google.com A` → 正常应答；named 在跑 |
| 权限未被放宽 | `named.conf` **0640** `_bind`、`rndc.conf` **0600**、zone 文件 **0644** ✓ |
| 无临时文件残留 | `etc/` 与 `zones/` 目录下无 `*.tmp*` ✓ |
| 单测 | 新增 `write_atomic_replaces_content_and_keeps_mode`（内容换新 + 权限仍是指定值 + 不留 tmp）→ **214/214** |

**顺带的自我提醒**：这轮 patch 被 MSYS 的反斜杠处理坑了两次（heredoc 里 `\n` 被吞成真换行、
带 `\"` 的锚点匹配不上），以及一次 `format!(...)` 少写 `.as_bytes()`（编译期抓到）。
**结论**：改 Rust 源码的 Python 锚点里不要出现反斜杠或引号，用「不含引号/反斜杠的短锚点」。

### 21.24 ECH 的开关**是假的**：`ech_advertise` 默认 true 让 `ech = false` 放行了整条自动配置路径（真红/真绿 + 现场探针 + 三条自检）

**怎么发现的**：§21.23 部署后扫启动日志，看到两条 WARN 恰好落在我第一次连 9445/9446 的时刻 ——
而这两个 listener **根本没配 ECH**（config.toml 里只有 8443 有 `ech = true`）：

```
WARN webserver::server::tls::boring_path] ECH 自动配置不可用（配置 ssl.ech_public_name 后可用）:
     ech_public_name 未配置：无法生成 ECH 配置; continuing without ECH
```

**根因**：`apply_ech` 的提前返回写成 `if !ssl.ech && !ssl.ech_advertise { return Ok(()) }`，而
`SslConfig::ech_advertise` 的 serde 默认值与 `Default::default()` **都是 `true`**（config.rs 里
唯一那个非平凡默认值）⇒ 该判据对**任何** TLS listener 都放行，每个 listener 首次构建 acceptor
（缓存懒建）都会走一遍 ECH 材料装载。两个后果：

1. 没配 ECH 的 listener 每次首连刷一条吓人的 WARN；
2. **更严重**：若 listener 配了 `ech_public_name`（它同时是 `ocsp_host()`，即 OCSP 自动装订的
   身份来源，本来就常配）而把 `ech` 显式关掉 —— 自动配置会**生成密钥、落盘、并 `set_ech_keys`
   装进 acceptor**。`ech = false` **什么都关不掉**；而 DNS 侧发布判据 `ech_advertise_enabled()`
   （要求 `self.ech && …`）又认为「没开」⇒ 可以同时存在「服务端在跑 ECH、DNS 不敢发布、
   面板显示 ECH 已关」这种自相矛盾的状态。

**修法**：判据只认 `ssl.ech`（`if !ssl.ech { return Ok(()) }`），关掉就是一点材料都不装；
`ech_advertise` 只保留字面职责（要不要把配置发到 HTTPS(type65) 记录）。反向情形
（`ech = true` 但 keys/public_name 全缺）仍照旧 warn「开了却没生效」。

**红/绿（走了三步才拿到真证据，过程本身值得记）**：

1. 第一版测试用**自建材料**当客户端，配旧判据跑「红」—— **红跑通过了**。原因：自动配置让
   **服务端自己生成**了另一份密钥，客户端手里的 ECHConfigList 对不上，`ech_accepted()` 在
   两种实现下都是 false。**两种实现都通过的测试不是回归测试**。
2. 更早那轮「红」其实什么都没改：OpenBSD 的 `sed -i ''` 写在脚本里**静默不生效**（跑完文件
   没变）。现在脚本加了自检：替换后必须 grep 到旧判据，否则 `exit 7`，不产出结论。
3. 最终改用**子进程 + 临时 cwd**：`ech_auto::state_dir()` 是 cwd 相对的 `state/ech`，而本项目
   的 `cargo test` 就跑在仓库根（= 生产目录），所以只有把 acceptor 构建放进临时目录，才能既
   **观察到材料有没有落盘**、又**不碰生产材料**。带**正对照**（`ech = true` 必须写文件）与
   `1 passed` 输出断言（`--exact` 过滤名写错时 cargo 仍 exit 0 —— 没有这条断言，测试可能
   因「压根没跑到目标用例」而永远为真）。

| 阶段 | 判据 | 结果 |
|---|---|---|
| 红 | `!ssl.ech && !ssl.ech_advertise` | **RED_EXIT=101**：`ech = false 时不得生成/落盘 ECH 材料（/tmp/…/ech_keys.pem 被写出来了 ⇒ 开关失效）` |
| 绿 | `!ssl.ech` | **217/217 passed**（补完三条自检后 220/220） |

**现场探针 `src/bin/ech_probe.rs`（顺带说明为什么不用 curl）**：本机 curl 8.21.0 是 **LibreSSL
后端**，`--ech` 只有帮助文本、实际报 `the installed libcurl version does not support this`。
于是拿我们自己依赖的 `boring` 写了个客户端：读 `state/ech/ech_config_list.bin`、对线上端口做真
ECHClientHello，打印 `ECH_ACCEPTED=` / 对端证书 CN/SAN/SHA256，握手后再**真的发一次请求**
（「握手成功却传不了数据」同样是坏的）。对生产 8443 实测：

```
ECH_ACCEPTED=true   PEER_CN=crucible.local   HTTP_FIRST_LINE="HTTP/1.0 200 OK"
--no-ech 对照：ECH_ACCEPTED=false，HTTP 200（回落外层正常）
```

外层名（ECHConfig 的 public_name，从 key 文件解出）是 `crucible.local`、内层真实名是探针传的
`prod.crucible.local` ⇒ **服务端确实用我们的 ECH 私钥解开了 ClientHelloInner**。并且关掉开关
的修为真机可见：重启后连 9445/9446，当前实例里 `ECH 自动配置不可用` 计数 **0**（旧实例里是 2）。

**顺手补上三条「配置分散两处、无人对照」的启动期自检**（`ech_selfcheck_problems()`，返回问题
列表而不是直接 log，便于单测断言什么配置该报、什么不该报；配了 3 个单测）：

1. 要广告却没发布（`ech_advertise` 默认 true，而真正的发布动作在 `[[dns.https_rr]]`）；
2. **启用了 ECH 却没配 cover 证书** —— 内外层会共用同一张真实证书；
3. DNS 发布了 `ech=` 却没有 listener 在服务它（客户端白试一次再回落）。

判据里「服务中的 public_name」优先配置项、其次**读密钥文件里的 ECHConfig**（`ech_keys` 形态下
public_name 只写在密钥文件里）。这里踩了一次：直接把 `persisted_config_list()`（**ECHConfigList**，
开头多 2 字节总长）喂给 `parse_config`（要 **ECHConfig**）解析失败，自检把名字显示成「未声明」；
现在解析归 `ech_auto::persisted_public_name()` 管，真机日志确认显示 `public_name=crucible.local`。

**生产现状（两条真实、可执行的告警，需要证书材料，不是代码能补的）**：

```
ECH: listener 0.0.0.0:8443 开了 ech_advertise（服务中的 public_name=crucible.local），
     但 [dns] 里没有对应的 [[dns.https_rr]]（name="crucible.local"、ech=true）—— ECH 不会被发布
ECH: listener 0.0.0.0:8443 已启用 ECH，但没有配置 cover 证书（ssl.ech_cover_cert / ech_cover_key）
     —— 外层会拿到与内层相同的真实证书，public_name(crucible.local) 那层伪装等于不存在
```

对照 `cert.pem` 实测：自签 `CN=crucible.local`、**无 SAN**、有效期 2026-08-25→2036 —— 也就是说
现在「外层名」和「内层真实名」用的是同一张证书，且内层名 `prod.crucible.local` 根本没有证书覆盖
（真实客户端按内层名校验会失败）。要按需求「内外层不共用一张 SSL」上线，需要：给 public_name
配一张 cover 证书（`ssl.ech_cover_cert/ech_cover_key`）、给内层真实名配真实证书，并在
`[[dns.https_rr]]` 里发布 `ech=`。

**教训（比这次改动本身更值钱）**：① 任何「开关」都要有**判别性**测试 —— 在旧实现下必须失败，
否则等于没测；② 测试脚本里做源码替换必须**自检替换生效**（OpenBSD sed 静默失败 + `--exact`
过滤名写错都只会表现为「通过」）；③ `state_dir()` 这类 cwd 相对路径，在「测试就跑在生产目录」
的项目里意味着**测试会写生产数据** —— 凡涉及它的检查都要放到临时 cwd 的子进程里跑。

**补记**：探针第一次被我拿 `| head -1` 截断时 panic 了（Rust 默认忽略 SIGPIPE ⇒ `println!` 撞 EPIPE）。
诊断工具被管道截断是正常用法，已在 `main()` 开头把 SIGPIPE 恢复默认处置；`bin/ech_probe` 是独立文件、
不随服务进程，换新二进制不需要重启服务，实测 `| head -1` 干净退出、完整输出仍为 `ECH_ACCEPTED=true`。

### 21.25 三个审计 agent 的报告 → 修复批次（QMux 无界缓冲 + 部分发送重复 / 一批 validate 缺口 / 部署钩子入库）

三个只读审计 agent（A：h2/h3/QMux/CONNECT-UDP；B：管理面/WebUI；C：热加载/validate/脚本）都交了报告
（`_audit_a.md` / `_audit_b.md` / `_audit_c.md`）。逐条**自己复核后**动手的与**看清但留待**的分列如下。

**已修（每条都有单测或真机复验）**

| 项 | 位置 | 错在哪 / 后果 | 修法 |
|---|---|---|---|
| QMux 入向记录无上限（A-P1-1） | `qmux/proto.rs` `RecordReader::next_record` | 记录头的 Size 被原样当作「还要收多少字节」，从不与 16382/协商值比较 ⇒ 任何能连上 QMux 的客户端发 8 字节 `FF…FF` 就能让我们**按声明值无界涨内存**（未认证 OOM） | `RecordReader` 加 `max_record_size`（默认 16382，`set_max_record_size` 只允许调大，§5.2）；**先查上限再缓冲**，超限立刻 `FRAME_ENCODING_ERROR`。`drain_records` 每轮从 `peer_max_record` 同步。单测 `declared_record_size_is_capped_before_buffering` |
| QMux 部分发送重复已发前缀（A-P1-3） | `qmux/conn.rs` `poll_write` | 部分入队后 `truncate(len - left)` **保留的是已发前缀**、丢掉的是未发尾部（注释写的意图与之相反）；下一次 `flush_frames` 把该前缀按已推进的 offset **再发一遍** ⇒ 对端读到重复字节（慢读的正常客户端也中招） | 改为清空缓冲（未发尾部交给调用方重发，符合 AsyncWrite 语义）。端到端回归 `partial_send_does_not_duplicate_prefix`（客户端把额度压到 1 字节 ⇒ 必然部分成帧，逐字节比对） |
| `admin.realm` / `basic_auth.realm` 未校验（C-10） | `config.rs` `validate()` | realm 含换行/引号/中文 ⇒ `WWW-Authenticate` 构造失败，而调用点 `.unwrap()` ⇒ **每个匿名 admin 请求 panic** | 新增 `safe_header_value()`（可打印 ASCII、不含 `"`/`\`）+ `realm_fields()`，配置期拒绝 |
| `admin.path` 未校验（C-11） | 同上 | `"/"` 让管理面匹配一切路径（接管整站）；`"admin"` 缺前导斜杠 ⇒ 面板静默 404 | 配置期要求非空、以 `/` 开头、且不是 `/` |
| `listeners = []` 通过校验（C-8） | 同上 | reload 成功后所有 accept 循环退出 ⇒ 进程活着但**全站停服**，日志只有一行 | 配置期要求至少一个 listener |
| TLS 材料路径不检查（C-12） | 同上 | `ssl.cert` 路径打错 ⇒ reload 通过、每次握手失败被 soft-fail 丢弃 ⇒ 端口静默下线 | 校验 cert/key/cert_ec/key_ec/cover 的存在性（内联 PEM 除外；`ech_keys`/`ocsp_der_path` 仍有运行期降级路径，故不强制） |
| `rate_per_sec = 0`（C-15） | 同上 | 令牌不再补充 ⇒ burst 用完后**永久 429** | `enabled` 时要求 `rate_per_sec > 0 && burst > 0` |
| proxy 规则空 path / 空 upstream（C-14） | 同上 | 空 path 的规则**永不匹配**且无告警 | 要求 path 非空且以 `/` 开头、upstream 非空 |
| `autoindex.paths = [""]`（C-19） | 同上 | 空串裁尾斜杠后恒真 ⇒ 上传/目录列表覆盖**整站** | 要求条目非空且以 `/` 开头 |
| 相对路径基准不一致（C-13） | `resolve_paths` | 只有 cert/key/cert_ec/key_ec 按配置目录解析，`ech_keys`/cover/OCSP 走**进程 cwd** ⇒ 换 cwd 启动时 ECH 静默消失 | 全部 9 个 TLS 材料字段统一按配置目录解析 |
| `admin_geoip::json_str` 不转义控制字符（B-F4） | `admin_geoip.rs` | 值里一个换行 ⇒ 整个响应非法 JSON ⇒ 该面板模块不可用 | 改用 `serde_json::to_string`（`json_escape` 同理剥引号） |
| 部署钩子不在版本控制（C-20/C-21） | `scripts/` | `/etc/rc.local`、`daily.local` 只存在于生产机；`*.sh` 被 gitignore 吞掉 ⇒ 启动方式不可评审/不可复现 | 两份 `.local` 已入库（去掉重复注释）；`start_server.sh`/`build_release.sh` 重写：**删除 openssl 依赖**（本项目明确不依赖它，旧脚本用 `openssl req` 静默生成自签证书）、启动统一委托 `/etc/rc.local`（C-23 的错目标、C-24 的 /tmp 日志一并消失） |

**看清楚了但**没做**（连同理由，避免「以为修了」）**

- **h3 缺全局在飞预算**（A-P1-2）：h2 有进程级 256 在飞闸门，h3 只有「每连接 100」+ 无连接数上限 ⇒
  理论内存上界 = 连接数 × 100 × 8MiB，攻击者可控。修法明确（照抄 h2 的信号量），但会动到 h3 请求
  生命周期，**留到下一轮**专门做 + 压测。
- **CONNECT-UDP 无开关**（A-P2-1）：默认开启的任意公网 UDP 中继（内网地址已被拒，不是 SSRF）。
  需要新增 per-listener 配置项（面板/文档同步），下一轮。
- **证书轮换不重载**（C-1）与 **H3 证书/设置不随 reload 更新**（C-3）：acceptor 缓存键里只有配置
  字符串，证书文件被 ACME 原地替换后进程继续用旧证书。修法是把材料 mtime/size 进指纹 + 让 h3 任务
  在 reload 时重建，属结构性改动，下一轮。
- **`root` 防自曝校验可被 `"./"` 绕过**（B-F3）：面板侧只比字面量 `"."`/`".."`，需 canonicalize 后
  与配置目录比较；涉及「绝对路径 root 是否合法」的产品决定，留待与运维确认。
- **仓库自带 admin 示例口令**（B-F1）：`config.toml` 里带着 `admin` 的可用哈希、且 `[admin]` 未设
  `listeners_allow` ⇒ 面板等同无鉴权。这是**部署决定**（需要你给新口令），我加不了。
- 其余小项（QMux 窗口更新可丢 P2-2、流数按累计计 P2-3、port_reuse 无超时 P2-4、acceptor 缓存上限
  64 < listener 上限 128 C-5、坏配置刷日志 C-7、`replace()` 死代码 C-6、`[dns]` 覆盖 C-17、
  geoip 假开关 C-18）已记录在 `_audit_*.md`，按优先级后续处理。

**另外**：顺手补了 rustls-only（不带 boring）回归 —— `cargo check` 0 错误、`cargo test` **200/200 全绿**，
证明本轮的 config/自检/恢复代码在无 BoringSSL 配置下同样成立。

### 21.26 审计遗留第二批 + 第三批：h3 在飞闸门 / CONNECT-UDP 默认关 / 证书轮换进指纹 / root 自曝封堵 / QMux 窗口更新不丢 / port_reuse 超时

**第二批（有配套单测，测试 231 passed / 0 failed / 1 ignored，已部署复验）**

| 项 | 位置 | 错在哪 / 后果 | 修法 + 证据 |
|---|---|---|---|
| h3 缺全局在飞预算（A-P1-2，P1） | `h3.rs` | h2 有进程级 256 在飞闸门，h3 只有**每连接** 100 条流 ×8 MiB body，而 QUIC 连接数不限 ⇒ 内存上界 = 连接数 × 800 MiB，攻击者决定；收 body 还在 ip_access/限流/口令**之前**，未认证即可发起 | 新增 `H3_MAX_INFLIGHT = 256`（与 h2 同值）+ 进程级 `Semaphore`，在 CONNECT 分流前、收 body 前取名额，5s 等不到回 503+Retry-After。单测：闸门进程级共享（一处持有、另一处可见）、与 h2 同值 |
| CONNECT-UDP 默认可用（A-P2-1，P2） | `h3.rs` + `config.rs` | 反向代理/上传都要显式配置才开，CONNECT-UDP 却「不配任何东西就有」：公网 UDP 中继面（内网地址已被拒，不是 SSRF，但可用于流量洗白） | 新增 per-listener `connect_udp`（默认 **false**），未开启时 CONNECT 直接 403 并说明怎么开。单测钉住默认值与按 listener 生效 |
| 换证书不重载 = 继续用旧证书（C-1，P1） | `tls/boring_path.rs` | acceptor 缓存指纹只含配置**字符串**（=路径），ACME/certbot 原地续期后指纹不变 ⇒ 端口继续出示旧（甚至已过期）证书直到 reload/重启 | 指纹里加入 8 个材料文件的 **mtime + size**。单测：等长替换也必须改变指纹（只编 size 的实现会漏） |
| root 可被 `"./"` 绕过自曝检查（B-F3，P2） | `config.rs` `Config::load` | 面板侧只比字面量 `.`/`..`，`"./"`、`".//"`、绝对路径写成配置目录全都通过 ⇒ 该端口把 `config.toml`（含管理员口令哈希）当静态文件公开；`root = "state"` 还能读走 rndc key / ECH 私钥 | 在 `load` 里对**解析后**的 root 比较：等于配置目录、或是它的祖先，一律拒绝（后者会连 `state/` 一起暴露）。单测覆盖 8 种绕过写法 + 4 种正常 root |
| QMux 窗口更新可丢（A-P2-2，P2） | `qmux/conn.rs` | `on_consumed` 用「机会式」`push_one` 发 MAX_STREAM_DATA/MAX_DATA，队列满即丢，而「剩余 < 窗口/2」这个触发条件在额度推进后不再满足 ⇒ 对端永远等不到额度，双方互等到超时 | 改成 pending 记录（流级 + 连接级）+ `flush_window_updates()` 每轮补发；serve 主循环每轮调用一次 |
| port_reuse 无任何超时（A-P2-4，P2） | `port_reuse.rs` | h1/h2/h3 都有空闲超时，这条 SNI 直通路径一个都没有：慢速连接/不回包的目标可无限占用连接与 FD | 5s 连接超时 + 60s 空闲超时（每方向各一个带超时的 copy） |
| `status_path` 等路径项（C-16） | `config.rs` | 写错即静默 404，无任何提示 | 配置期要求非空且以 `/` 开头 |
| geoip 假开关（C-18） | `config.rs` | `enabled = true` 但无 `db_path` ⇒ 面板显示已启用、查询全部落空 | 配置期拒绝 |

**第三批（`validate` 剩余小项 + 卫生项）**：`telemetry.path`/`dns.doh.path` 的 `/` 校验、
acceptor 缓存上限 64 → 256（`MAX_LISTENERS = 128`，满上限会整表清空导致命中率归零）、
`LiveConfig::replace()` 与 `reload()` 同副作用（它曾是死代码，但被拿去局部热更就会
静默绕过缓存清理与 mtime 记账）、坏配置的 watcher 告警**去重**（以前 2s 一条 ≈ 4.3 万条/天）。

**诚实说明**：第三批这四项**没有配套单测**（都是小改动，靠代码推理 + 部署复验），
下一轮补上（尤其 `validate` 的两条，与 batch 2 的写法一致，加测试很便宜）。
第二批的六项都有单测，测试从 222 → **231 passed / 0 failed / 1 ignored**。

**部署复验（两批各一次，均为 1 实例）**：h1 200 / h2 200 / **h3 200（HTTP/3）** /
`ech_probe` `ECH_ACCEPTED=true` / DNS `dig` 正常 / PHP 引擎 200 / `__admin` 401。
新校验没有误伤生产配置（启动日志里只有预期的两条 ECH 待办与既有的 jsp reconcile 告警）。

**仍未做**：C-3（h3 的证书与 per-listener 设置不随 reload 更新，结构性）、
A-P2-3（QMux 流数按累计计，需要流生命周期回收，风险高于收益）、C-9（端口 bind 失败每 2s 告警）、
C-17（`[dns]` 零校验 + `panel.toml` 整体覆盖）、C-4（连接期配置冻结）、
以及需要运维决定的两项（admin 示例口令、ECH cover 证书）。全部记在 `_audit_*.md` 与本节。

### 21.27 **发现 4 个源文件只有本地版本、从未上传**（含两项安全加固）+ 一处判断更正

**背景**：批次 4 的编译一直报 `cannot find value MAX_LISTENERS in module ...admin_config_edit`，
而本地那份文件明明有。于是做了**逐文件字节对比**（本地 vs 生产 `/crucible`，比对全部 118 个 `.rs`），
查出 4 个文件本地比远端大、且远端从**未被上传过**：

| 文件 | 差值 | 里面是什么 | 后果（在此之前） |
|---|---|---|---|
| `src/server/ocsp_fetcher.rs` | +13.7 KB | OCSP 缓存加固：叶子证书指纹做缓存键、CertID 序列号匹配、`response_covers_leaf`（**这份 staple 是否真的覆盖当前叶子**）、原子写缓存、旧缓存文件迁移 | 通道里那些加固**没有生效** |
| `src/server/admin_config_edit.rs` | +11.2 KB | 配置写盘上限：`MAX_LISTENERS=128` / `MAX_APPS_PER_LISTENER=64` / `MAX_RULES_PER_LISTENER=512` / `MAX_ADMIN_USERS=64` / `MAX_TOML_TEXT_BYTES=2MiB` 等 + 校验辅助 | **面板/TOML 编辑器可以写进十万条**，把 `Config::load`+序列化+热重载一起拖死 |
| `src/server/tls/cipher_catalog.rs` | +3.9 KB | BoringSSL 套件表枚举（`SSL_get_cipher_by_value` 扫 IANA 编号空间）+ 目录/探针合并 | 见我下面的**判断更正** |
| `src/server/dns/geoip.rs` | +532 B | 一个测试辅助函数 | 无 |
| **`src/server/dns/geoip.rs`（第二处）** | — | — | — |

**教训（工作流层面）**：这轮还有一次 `_put.py` **静默失败**（输出被我吞进 /dev/null），
是靠远端 `grep` 才发现文件根本没上去。之后所有上传都改成「上传后立刻在远端比对字节数」。
**这两件事合起来说明：唯一可信的判据是「远端文件的实际内容」**，而不是「我以为我上传了」。

**一处必须更正的判断**：我曾判断「BoringSSL 支持、但我们手抄名单里没有的套件名会被误拒」，
并写了断言「枚举结果一定比手抄名单多」。**在 OpenBSD 上实测为假** —— 本机 BoringSSL 的套件表
与 `CANDIDATES` **恰好一致**（22 项，全部重合）。因此：
* 那条断言**已删除**，换成可验证的**超集关系**（枚举不得丢掉手抄候选中 BoringSSL 认可的名字）；
* 模块文档写明了这次更正：枚举的价值是「不再依赖假设」（换 BoringSSL 版本/构建选项后表会变），
  而**不是**「名单一定会漏」。我之前的判断在这台机器上不成立。

**编译期还修了一个真错误**：`ocsp_fetcher.rs` 里写了个闭包 `|s: &[u8]| -> &[u8]` ——
闭包的返回引用**拿不到**「返回值生命周期来自参数」的自动推导（elision 只对 `fn` 生效），
直接 `lifetime may not live long enough`。已改成独立 `fn strip_leading_zeros`。

**结果**：`cargo test` **242 passed / 0 failed / 1 ignored**（这批文件带来 11 个新测试），
`cargo build --bins` 通过，已部署并复验：1 实例、h1 200、h2 200、**h3 200（HTTP/3）**、
ECH 现场探针 `ECH_ACCEPTED=true`、DNS 正常、PHP 200、`__admin` 401。

### 21.28 h3 随 reload 更新（C-3）+ 批次 6 + **我用新校验第二次打挂生产**（以及真正的防护：`--check-config`）

**C-3（h3 端点不随 reload 更新）**：`h3::serve()` 启动时一次性读入证书、之后每连接的 `lc` 都是
冻结克隆 ⇒ 换证书/改 `early_data`/改限流口令对 H3 **一律不生效**，直到进程重启。
修法：给每个 h3 端点一条 `watch<u64>` **指纹通道**（整份 lc 的 Debug 形式 + 证书/私钥文件的
mtime/size）——`mod.rs` 的 reconciler 每 2s 算一遍并喂进去；`serve()` 里挂一个看门狗，值变了就
`endpoint.close()`，让 `while let endpoint.accept()` 自然收尾、由外层用**最新配置**重启端点。
真机验证：`touch /crucible/cert.pem` → 日志
`h3 endpoint config/materials changed; closing QUIC endpoint to restart with new config`
→ `h3 quinn endpoint ready on 0.0.0.0:8443` → h3 仍 200、ECH 仍 accepted。

（第一版把 `select!` 插进了**每连接**的 `handle_incoming` 循环而不是端点循环 —— 两个循环长得很像，
锚点撞了。改成看门狗后改动面更小，也不再有「配置一变就砍在飞连接」的歧义：端点重启本来就会
重连。）

**批次 6（C-9 + C-17）**：
* C-9 端口 bind 失败以前**每 2s 一条 warn**（≈4.3 万条/天）→ 同一端口同一条错误只报一次；
* C-17 `[dns]` 缺校验 + `panel.toml` 整体覆盖无人知 → 新增 `https_rr[].name` 非空校验，
  并在 `dns::effective()` 里对**生效配置**（panel.toml 那份）做检查 + 进程内只提示一次。
  真机日志（本次部署后）：
  `dns: /crucible/state/dns/etc/panel.toml 存在且生效 —— config.toml 的 [dns] 被**整体覆盖**
  （两者内容不同，当前生效的是面板文件）；在 config.toml 里改 [dns] 不会生效` ✓

**事故（我造成的第二次停机）**：批次 6 里我给 `validate()` 加了一条
「`dot.enabled = true` 必须有 `dot.cert`/`dot.key`」，而生产的 DoT 证书其实来自 `panel.toml`
（它**整体覆盖** `[dns]`），config.toml 里的 `[dns.dot]` 只写了 `enabled/port`、**从未被使用**。
校验看 config.toml、运行用 panel.toml ⇒ **误拒**，部署后进程启动即退出（`rc.local` 打印了
`started pid`，但实例数 0、全站 000）。
处置：① 先让配置自洽（给 config.toml 的 `[dns.dot]` 补 `cert/key` —— 运行时仍被 panel.toml 覆盖，
**零行为变化**）→ 站点恢复；② 删掉那条校验（注释写明原因），检查改到 `effective()` 里对着
**真正生效**的配置做、且只 warn。

**真正的防护：新增 `--check-config`** —— 只做「加载 + 校验」后退出，不绑端口、不起服务：

```
./bin/webserver.new --config /crucible/config.toml --check-config
config OK: /crucible/config.toml (listeners=5, apps=18)
```

部署流程从此变成：**build → 预检（新二进制 × 当前生产配置）→ 通过才停-换-起**。
这是同一个坑第二次踩（第一次是 `autoindex.paths = ["/"]`），所以把它写进流程而不是靠记性。
本次部署就是这么做的：预检 rc=0 → 换二进制 → 1 实例、h1/h2/h3 全 200、ECH accepted、DNS 正常。

### 21.29 QMux 并发额度归还（P2-3）+ 上传闸门与落盘 root 改读 live 配置（C-4）

**P2-3（QMux 流数被当成「累计开流数」）**：`initial_max_streams_bidi` 是**并发**额度
（RFC 9000 §4.6），而实现里是单调计数器 `peer_bidi_opened` 且 `streams` 表**永不删条目** ——
一条 QMux 连接**总共**只能跑 100 条流，第 101 条直接 `STREAM_LIMIT_ERROR` 并把连接关掉
（长连接上的合法客户端被误杀）。修法：
* 额度判据改成「**当前活着的流**数」（判定时正持有 `streams` 锁，`len()` 与判定天然一致）；
* 新增 `Conn::maybe_retire_stream`：双向都收到/发出 FIN（或对端 STOP_SENDING 且我已 FIN）
  就把条目从表里摘掉、归还额度，挂在三处——收到对端 FIN、我方 FIN 发完、收到 RESET_STREAM；
* 删掉已无用的 `peer_bidi_opened` 字段。
* 回归测试 `stream_budget_is_released_after_close`：**顺序跑 120 条流**（>100），全部要成功，
  且最后再打一次 QX_PING 仍要有回显（连接没被关）。旧实现下第 101 条就会断连。

**C-4（请求期配置冻结）**：上传闸门尺寸取自 `lc.autoindex.upload_threads`，而 `lc` 是**建连时**
的快照 —— h1/h2 长连接可存活数小时，期间面板「关上传 / 收紧并发 / 改 root」只对新连接生效，
旧连接照旧收上传、往旧 root 写。上传是**写盘面**，`enable_upload: true → false` 不能有窗口。
修法：
* `live_config::listener_by_port(live, port)`：按端口取**当前生效**的 listener 配置；
* `upload_api::enabled_for` 与三个入口（`handle`/`handle_stream`/`handle_bytes`）加 `live` 参数，
  `handle` 进来就按端口取当前配置（取不到才回退调用方的快照），闸门与落盘 root 都用它；
* `enabled_for` 同样按当前配置判 —— 否则「已关上传」的连接连 405 分流都不会走。
* 7 处调用点（h1 ×1、h2 ×3、h3 ×3）同步传 `live`；单测里那个用默认配置断言「不接管」的用例
  改成构造最小 `LiveConfig`（新签名要求）。

测试：**244 passed / 0 failed / 1 ignored**（P2-3 与 https_rr 两条新用例在内），已按新流程部署
（`--check-config` 预检 → 停 → 换 → 起），复验 h1/h2/h3 全 200、ECH accepted、DNS、PHP。

### 21.30 listener 绑定键含地址（审计 C-2，最后一条 P1）+ 管理面 listeners_allow 告警（B-F2）

**C-2 的两个静默表现**（都属于「运维以为改了，其实没效果」）：
1. 把某 listener 的 `address` 从 `0.0.0.0` 改成 `127.0.0.1`（端口不变）后 reload：
   报成功、日志说 binds changed，但 socket **不重建** —— 仍绑在 0.0.0.0。以为收紧了
   暴露面，实际全网可达（反向改动则是「改了没生效」）。
2. 同端口不同地址的两个 listener：配置能过校验，但按 port 去重只会绑第一个，
   第二个**永不监听且无任何告警**；即便绑上，连接分发按 port 取配置也会取错站点。

**修法**：
* 新增 `server::bind_key(lc)` = `"address|address_v6|port"`；`active` 集合（已激活判定）、
  accept 循环的存活判定、h3 任务的存活判定全部改用它 —— 地址一变，旧循环退出、新循环按新地址绑定；
* 「实际接受连接的那个 socket 地址」透传给 `listener::handle_connection`，
  连接分发按 **端口 + 地址** 选配置（新增 `listener_matches_local`，通配地址按同族匹配，
  并回退到「同端口第一个」以免行为退化）；
* 同端口不同地址的两个 listener 从此**各自绑定**（地址不冲突时都能起来；冲突时 bind 失败会
  **明确报错**，而不是静默只绑一个）。
* 仍按端口寻址的地方（面板 API、上传闸门的 live 查询）保持原样并注明：那两处是既定接口，
  同端口不同地址属边缘部署。

**B-F2**：`[admin].listeners_allow` 为空 = 管理面在**所有** listener 上可达（含明文 HTTP 端口，
Basic 凭据明文上线、防爆破面扩到全部端口）。这是「默认值站在不安全的一侧」，加启动期告警。

**真机验证（C-2，含一处对先前说法的更正）**：临时追加 `127.0.0.1:18080` → `netstat` 显示
`tcp 0 0 127.0.0.1.18080 LISTEN` 且能应答 ✓；把 `address` 改成 `127.0.0.2` 后 reload，日志：

```
config reload: listener binds changed (added=[("127.0.0.2", 18080)] removed=[("127.0.0.1", 18080)])
hot-spawn listener 127.0.0.2||18080 failed: bind 127.0.0.2:18080: Can't assign requested address
listener 127.0.0.1||18080 removed/changed in config; shutting down accept loop
```

**三条都在证明修复生效**：① reload **识别出绑定变了**（旧代码只比 port，会判定「什么都没变」，
socket 不重建）；② 旧 socket 被**主动退休**（旧代码会一直绑着 127.0.0.1）；③ 新地址绑不上时
**大声报错**，而不是继续用旧绑定假装成功。

**更正**：我起初以为「127.0.0.2 也是 loopback、可以绑」，实测在本机**不行** ——
`nc` 同样报 `Can't assign requested address`，`ifconfig lo0` 只有 `::1`（v4 侧仅有 127.0.0.1）。
所以第 2 步的「新地址没监听」不是缺陷，而是**真实的绑定失败 + 如实上报**；这条更正也说明
「换地址」这类验证必须挑一个本机确实可绑的地址，或像这里一样把失败路径当作验证目标。

（验证脚本 `_vfy_c2.py` 每次都会还原 config.toml；本次已还原并复验生产 5 个 listener 正常。）

### 21.31 补上 C-2 / C-4 的判别性单测（我欠的账）+ 交叉特性配置回归

**为什么这三条测试值得单独写**：C-2（绑定键）与 C-4（闸门读 live）都只做了真机验证 ——
真机验证证明「现在是对的」，但**挡不住**以后有人把它们改回去。三条测试各钉一个退化方向：

1. `server::bind_key_tests::bind_key_includes_address_v6_and_port`：把「同端口不同地址 ⇒
   不同键」钉住 —— 没有它，有人把 `bind_key` 简化成 `port.to_string()`（就是 C-2 的旧行为）
   不会有任何测试变红；同时断言同参数**稳定**（去重与存活判定依赖它）。
2. `listener::match_tests::matches_by_port_and_address`：连接分发选配置的判据 ——
   精确匹配、端口不同不匹配、地址不同不匹配（否则同端口两个站点会串）、
   通配 `0.0.0.0` 匹配任意 v4 本地地址（生产就是这种）但**不**匹配 v6 本地地址、
   `address_v6` 参与匹配。
3. `upload_api::tests::enabled_for_follows_live_config`（C-4）：在**同一份 live** 上把
   `enable_upload` 从 false 翻到 true，断言判定**立刻翻转**，并保留路径边界断言 ——
   旧实现只看建连快照，这条会红。

**顺带**：本轮把「rustls-only（不带 boring）」的 `cargo check` 与 `cargo test` 也放进了同一次
回归（我这些改动动了 `mod.rs`/`listener.rs`/`upload_api.rs`/`h3.rs`，必须确认不带 BoringSSL 的
配置照样编译与通过），并在脚本末尾回收 `target/debug`（`cargo check` 的 dev 产物，磁盘长期 95%）。

**这一轮单测立刻抓到一个真缺口**（值得记）：`listener_matches_local` 里 `address_v6 = "::"`
（通配 v6）没被当成通配 —— 只做精确相等 ⇒ 配了 `address_v6 = "::"` 的 listener **匹配不上任何
v6 连接**（`0.0.0.0` 那侧是对称处理过的，v6 这侧漏了）。生产配置没有 `address_v6`，所以
真机验证看不见它；是刚写的单测把它逼出来的。已修（`v6.is_unspecified() && ip.is_ipv6()`）。

另外把上一轮标了 `#[ignore]` 的 QMux「部分发送重复前缀」用例**改成接收驱动版**（额度按已收字节
推进 + 总超时），消除了导致假红的竞态，现在它是这条 P1 修复的真正回归测试。
### 21.32 named 只在 loopback 监听（生产 53 收不到公网查询）——根因：`listen-on { 0.0.0.0; }` 被 BIND 静默丢弃

**这一节同时是两条更正**：一条是对「方案 A 已做完」的更正（R4 其实没达成），一条是对我此前
「外部 vantage 看到递归还开着」那批证据的更正（那批证据全是假的，见下）。

#### 现象
方案 A 落地后从**本机 loopback** 复验全绿（`. NS` 13 条真根 NS + `aa`、`com.` 转交、`com. DS`、
递归 `google.com A` + RRSIG），但用户要求的 R4「客户端把这个机子当根服务器查询」是**外部**判据：
从外网看 53 端口 **TCP 直接 refused**。`netstat`/`sockstat`/`fstat -p <named pid>` 三处一致 ——
named 只持有 `127.0.0.1:53`（UDP+TCP），**没有** `83.229.125.81:53`，而 `named.conf` 里明明写着
`listen-on port 53 { 0.0.0.0; 127.0.0.1; }`。`pf` 侧 53 是放行的，`rndc status` 显示的配置路径与
boot 时间也都是新的（说明不是「改了配置没重载」）。

#### 定位：一个对照实验就定性
在 5301/5302 端口起两个一次性 named 实例（`-g` 前台、独立目录、`fstat -p` 看 socket）：

| `listen-on` 内容 | named 实际建出的 socket |
|---|---|
| `{ any; }` | `127.0.0.1:5301`、**`83.229.125.81:5301`**、`10.126.126.1:5301` |
| `{ 0.0.0.0; }` | **一个都没有**（连 loopback 都没有），日志里**无任何告警** |

结论：named 的 `listen-on` 是**逐接口枚举**语义（不是 bind 一个通配地址）—— 关键字 `any` 展开成
「每个接口地址各建一个 socket」，而**字面量 `0.0.0.0` 匹配不到任何接口地址，于是被静默丢弃**。
`listen-on-v6 { any; }` 一直是对的（v6 地址全建出来了），所以只有 IPv4 这一侧漏；这也解释了
为什么 loopback 复验看不出来：`127.0.0.1` 恰好是我们**显式**列在 listen-on 里的那一项。

**自欺环节（必须留档）**：我此前用「外部 vantage」看到 `. NS` 超时、`google.com A` 却有答案，
据此以为「外部递归仍开着」。后来发现**本机 UDP/53 被运营商劫持**：向 `192.0.2.1`（TEST-NET-1，
RFC 5737 保证不可达）发查询也照样返回真实 A 记录；向真根 `198.41.0.4` 发 `com. NS +RD=0` 返回的是
带 `ra`、TTL 77952 的**递归器缓存答案**而不是 `aa` 转交。所以那批「外部证据」全部来自本地递归器，
与我们的 named 无关 —— **「没验证」和「验证了但证据是假的」是同一件事**。
现在外部视角一律走 **TCP/53**：劫持只拦 UDP（TCP 对 192.0.2.1 如实 connect 失败），
对真根 `198.41.0.4` 能拿到 `flags: qr`、`an=0 ns=13 ar=26` 的正经转交（`_dnsq.py` 已支持 `tcp` 模式）。

#### 修复（`src/server/dns/mod.rs`）
把 named.conf 的地址表生成抽成纯函数 `listen_lists(addr, test_mode, geo_lines) -> (listen-on, listen-on-v6)`：

- `0.0.0.0` → 关键字 **`any`**（绝不再落字面量）；`::` → v6 侧 `any`、v4 侧 `none`；
- v4 字面量 → v4 侧原样、v6 侧 `none`；v6 字面量 → v6 侧原样、v4 侧 `none`
  （旧代码在 `listen_addr = "::1"` 时把 **v6 表也写成 `none`**，等于「配了 v6 却哪里都不听」，一并修正）；
- `any`/`none`/`localhost`/`localnets` 关键字两侧透传；
- **`127.0.0.1` 永远补进 v4 表**（本进程 DoT/DoH 转发的源地址就是它，少了它每个查询被自己的
  named 回 REFUSED）；测试模式固定 `127.0.0.1` / `none`。

#### 顺带查出的第二个缺陷：分线路 loopback 地址少了中间那段 `0`
同一段代码里分线路转发地址写的是 `format!(" 127.0.{};", 2 + i)` ⇒ 生成 `127.0.2`、`127.0.3`…，
而另外三处用的都是 `127.0.0.{2+i}`：fwd view 的 `match-destinations { 127.0.0.{2+i}; }`、
`ifconfig lo0 inet 127.0.0.{2+i} alias`、以及 DoT/DoH 的 `resolve_fwd_dest`（返回 `127.0.0.(2+i)`）。
三处不一致 ⇒ **配了 geo 分线路时，fwd-<line> view 的 `match-destinations` 上根本没有 socket，
分线路转发静默失效**（生产 `geo.lines` 为空，所以一直没暴露）。已统一为 `127.0.0.{2+i}`，
索引范围与 `resolve_fwd_dest` 的 `i.min(250)` 对齐（可达 `127.0.0.2`..`127.0.0.252`），
且**分线路为 0 时一个都不加**。

#### 回归测试（8 条，`dns::listen_lists_tests`）
`wildcard_v4_becomes_any_never_literal`（钉住「绝不出字面量 `0.0.0.0`」）、
`loopback_is_always_in_v4_table_and_never_duplicated`、`v6_literal_never_leaks_into_v4_table`
（含 `::1` 时 v6 表必须是 `::1` 而不是 `none`）、`keywords_pass_through_to_both_tables`、
`geo_line_loopbacks_are_listed_explicitly`（含「老写法 `127.0.2` 不许出现」）、
`geo_line_loopbacks_cover_the_resolver_index_cap`、`no_geo_lines_adds_no_forwarding_loopbacks`、
`test_mode_is_loopback_only_even_with_public_addr`。

**其中 `no_geo_lines_adds_no_forwarding_loopbacks` 是「单测当场抓到我自己的 bug」**：我先把上限写成
`0..=geo_lines.min(250)`，`lines=0` 时 `0..=0` 会多加一个 `127.0.0.2`，两条既有用例立刻变红。
（另：这个包**没有 lib target**，测试必须用 `--bin webserver` 跑，`--lib` 会直接
`error: no library targets found` —— 我第一次就踩了这个，别把那个 101 当成测试失败。）

#### 真机复验（部署 2026-10-02 13:11，备份 stamp `20261002-131111`）
部署流程：build → `--check-config`（rc=0）→ 停 webserver **与 named** → 换二进制 → `sh /etc/rc.local` → 复验。
**必须显式杀 named**：reconcile 只判「named 活着与否」，旧配置下 named 是活着的，只重启 webserver
会让它继续用旧的 loopback-only 绑定（我第一次重启后 fstat 仍只有 `127.0.0.1:53` 就是这个原因）。

生成的配置（已落地）：`listen-on port 53 { any; 127.0.0.1; };` / `listen-on-v6 port 53 { none; };`；
`named-checkconf -z` OK（只有根区里 SHA-1 DS 的 deprecated 提示，那是真实根区的数据）。
named 实际 socket（`fstat -p 91042`）：`127.0.0.1:53`、**`83.229.125.81:53`**、`10.126.126.1:53`（UDP+TCP 各一）。

**外部视角（全部 TCP/TLS —— 本机 UDP/53 被劫持，见上）**：

| 查询 | 结果 | 判据 |
|---|---|---|
| `. NS` RD=0（TCP） | `qr aa`，an=13，ar=26 | 根服务器视角：权威回答 13 条真根 NS + glue |
| `. NS` RD=0（UDP，经公网 IP 自身） | `qr aa`，ANSWER 13，ADDITIONAL 27 | UDP socket 在公网 IP 上确实应答 |
| `com. NS` RD=0 | `qr`，an=0 ns=13 ar=26 | 正经转交（不是递归答案） |
| `com. DS` RD=0 | `qr aa`，an=1 | 根区里 com 的 DS，权威 |
| `com. NS` RD=0 +DO | `qr`，AUTHORITY 15，含 RRSIG(DS) | 签名转交 |
| `google.com A` RD=1（外部） | `qr rd`，an=0 ns=13 ar=26 | **无 `ra`、无递归答案** = 外部递归关闭 |
| DoT `83.229.125.81:853` `com. NS` RD=0 | `qr ra`，转交 | DoT 监听可用（`1.1.1.1:853` 作对照同样通过） |

**本机侧（loopback，UDP 可信）**：`google.com A` → `qr rd ra` + `142.250.197.46`；
`example.org A` → 有答案（确实在用我们自己的根迭代）。h1 9095/9081 → 200，h3 8443 → 200，
853/5349/8443/9445/9446 均在听；ECH 探针 `ECH_ACCEPTED=true`。

**遗留（不是 bug，是待拍板的策略）**：`panel.toml` 里 `dot.allow = ["0.0.0.0/0","::/0"]`（面板意图是对
所有人开 DoT），但 `recursion_acl` 只有 `127.0.0.1` ⇒ 公网 DoT 客户端只能拿到根区转交、拿不到递归答案。
取哪边是策略问题（开放递归 = 放大攻击面），我按「外部递归关闭」处理，并记进 `OPERATOR-TODO.md` E 项。
### 21.33 审计 C-21/C-22 收尾：部署脚本里的明文口令与「先删后传」；并更正 C-21（同步仓库其实早已入库）

**C-21 更正**：审计报告说「所有 `scripts/*.sh` 被 `.gitignore:84` 的 `*.sh` 整体忽略 ⇒ 启动/部署脚本
不在版本控制」，证据是 `git ls-files scripts | grep -c '\.sh$'` → 0。**这条对同步目标仓库不成立**：
在 `/crucible` 上 `git ls-files 'scripts/*.sh' | wc -l` = **41**，`git ls-files --others scripts/` 为空
（即全部已跟踪）。审计当时看到的是**本地快照仓库**（`C:\...\crucible`，基线提交 `caf3466`），
那份本来就只有部分文件，`scripts/*.sh` 确实一个都没跟踪 —— 结论是对本地副本成立、对生产仓库不成立。
不过 `.gitignore` 里 `*.sh` + 单文件例外的写法确实**易被后人改坏**，所以我把它改成语义明确的规则：
`*.sh` 保留（挡住各处一次性脚手架），随后 `!scripts/*.sh` + `!scripts/*/*.sh` 开例外，
并注明「gitignore 后来居上，例外必须写在 `*.sh` 之后」。

**C-22 修复**（本地-only 的两份部署脚本，都不在版本控制里）：

| 问题 | 处理 |
|---|---|
| `REMOTE_PASSWORD="<旧-SSH-口令-已脱敏，见 OPERATOR-TODO G>"` 明文硬编码（`deploy_remote.sh:7`、`deploy_to_remote.sh:9`），且 `deploy_to_remote.sh` 在 sshpass 缺失时**把口令打印到终端** | 改为只从 `CRUCIBLE_SSH_PASSWORD` 读；未设置则 fail-closed（打印指引 + `exit 1`，不做任何动作） |
| `deploy_remote.sh:42` 在生产机上 `rm -rf src target *.rs Cargo.toml Cargo.lock` 后解包重建 | 删除该路径；现在只做「覆盖同名文件的源码同步」，**不删任何远端文件** |
| `cp -r "$LOCAL_PROJECT"/*` 会把 `.git/`、`cert.pem`、`key.pem`、`state/`（rndc key、ECH 私钥、上传目录）一起打包上传 | tar 明确排除 `.git`、`target`、`bin`、`state`、`*.pem`、`*.key`、`*.log`、`*.zip` 与根目录脚手架 |

**新增入库的正路**：`scripts/deploy/deploy_release.sh` —— 通用发布流程
（可选构建 → 快照 → `--check-config` 预检 → 停 webserver → **同目录改名**换二进制 → 起 → 复验），
每步可回退，并在结尾打印精确的回退命令。与 `dns_listen_redeploy.sh` 分工明确：
后者用于 DNS/监听类改动（**额外显式重启 named**），本脚本只重启 webserver。

**顺带查出的真问题（已升级为运维待办 G）**：明文口令不只在那两个脚本里，还散在**根目录约 269 个
一次性 Python 脚手架**（`api1.py`、`b1.py`、`axfr*.py` …）中，且本地快照仓库的基线提交跟踪过
其中一部分（`api1.py` 等）。**被推送的仓库是干净的** —— `git grep -l 'Yc4' HEAD` 在
`sourcetf/crucible-source` 上无命中，口令从未进过远端仓库。缓解措施：
`.gitignore` 现在整体忽略根目录 `*.py`/`*.ps1`/`*.sh`（项目的真实 python 在 `scripts/` 与 `bench/`，
照常跟踪）。但**已落盘的明文口令只能靠轮换消除**，故记为 OPERATOR-TODO G 项
（换口令或改密钥登录；并强调「先确认密钥能登再关口令登录」）。

**验证**：`bash -n`/`sh -n` 两份新脚本通过；`grep -c Yc4` 三份根脚本均为 0；
不带 `CRUCIBLE_SSH_PASSWORD` 直接运行 → 打印指引并 `exit 1`（实测退出码 1，未做任何动作）；
`git check-ignore -v` 抽查：`scripts/start_server.sh`/`ech_demo.sh`/`deploy_release.sh` 均可入库，
`deploy_remote.sh`（根目录）仍被忽略。