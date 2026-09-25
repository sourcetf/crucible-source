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


### 21.5 build44 复验：h2 的 PUT 挂住**与上传无关**（预先存在的 h2 缺陷）

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

