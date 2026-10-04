# 第 6 轮判据脚本（引擎面 + 并发/竞态面）

这组脚本把第 6 轮的每一条判定**固化**下来，便于复审与回归。每条都写明「修复前会怎样」，
所以它们同时是**负控说明书**（在未修的二进制上跑，应当 FAIL）。

## 前置

1. 用测试配置起实例（**不要**在生产实例上跑 `r6_accept_emfile.sh`）：
   ```sh
   cd <repo> && ./target/release/webserver --config config-test.toml    # 端口 19095/9081/18443…
   ```
   注意：`config-test.toml` 默认**没有** `cgi_script` 应用，E7 会自动 SKIP 并打印补法。
2. 需要 `python3`、`curl`、`dig`（DNS 那条）。

## 脚本一览

| 脚本 | 判据 | 修复前 | 修复后（实测） |
|---|---|---|---|
| `r6_engine_faces.sh` | E1 三引擎回归 / E3 lua 固定文本 / E4 python 不得静默 200 / E5 php 不回显 docroot / E6 php 拿到 `.env` / E8 content-type 去重 / P2 超长 `.env` 值不吞后续变量 | E6 `APP_HELLO=` 空；E8 两个 content-type；P2 后续变量全丢 | 全 PASS（E6 `APP_HELLO=php`、E8 只剩 `application/json`、P2 `AFTER=[present] LONGLEN=[2500]`） |
| `r6_engine_faces.sh`（`R6_SLOW=1`） | E2 CGI 超时杀**孙进程** | `sleep 311 &` 在 502 后仍存活 | 无残留 |
| `r6_engine_e7_cgi_script.sh` | E7 `cgi_script` + 应用 `paths` 前缀 | 必然 404（去找 `docroot/<paths>/x.cgi`） | 200 + 目录回落 index.cgi |
| `r6_wsgi_asgi_500.sh` | E4（pyembed）wsgi/asgi 抛异常 | body 回显 traceback + `script=/绝对路径` | 500 + `wsgi: application error` / `asgi: application error` |
| `r6_upload_concurrency.sh` | #5 并发同路径全量上传 | 2×201 + 1×409 + **1×500**，一方数据静默丢失 | **1×201 + 3×409、无 5xx**，落盘单一来源、无 `.part` |
| `r6_accept_emfile.sh` | #1（**P0**）fd 打满后监听口不得永久死亡 | 释放 fd 后仍 **000**（该口永久下线，只有重启恢复） | 释放后 **200**；日志有节流重试且 `accept_loop ended=0` |
| `r6_net_timeouts.py empty <port> <wait> ...` | #2 明文口首字节嗅探超时 | 零字节连接**永不被关** | **32.4s** 被关（2.4s 嗅探预算 + h1 30s 头读超时） |
| `r6_net_timeouts.py h2 <port> <wait> ...` | #3 h2 半截 HEADERS | 110s 仍开着、无上限 | **300.0s** 被关（h2 空闲超时，nginx `http2_idle_timeout` 语义） |
| `r6_dns_named_watchdog.sh` | #4 named 存活看门狗 | kill 后 26s 内不重启，直到下次改配置 | **75s 内自动拉起**（新 pid）+ 看门狗日志 |

对应提交：`82e3aef`（引擎面）、`517edff`（并发/竞态面）。判定明细见 `contact.txt` 里工号 1008 的两节。

## 写这组脚本时踩到的判据坑（留档，别再犯）

* **OpenBSD `grep` 不支持 `\|` 交替**：`grep 'a\|b'` 静默无匹配（不是「没找到」而是「模式被当成字面量」）。
  一律改用 `grep -E 'a|b'`。同理 `head -c` 不存在（用 `head -c` 会报 unknown option）。
* **`pgrep … | wc -l` 的输出带前导空格**：`[ "$left" = "0" ]` 会假失败。要 `$(… | tr -d ' ')` 或算术比较。
* **`pkill -f <模式>` 会杀掉自己**：ssh 执行的命令行里若出现同一字符串（例如配置路径），
  模式会命中自己的 shell。要么用 `'r6[v]'` 这类括号技巧，要么按 pid kill。
* **`cp` 到正在被执行的二进制会 ETXTBSY**：`sh /etc/rc.local` 仍会「成功」拉起**旧**二进制
  ⇒ 看起来部署成功、其实没生效。部署前先确认 `pgrep -x webserver` 为空。
* **浏览器访问不了 ≠ 服务器不可达**：8443 是自签证书且用 IP 访问时证书名不符，浏览器会拦在
  证书警告页（`tls accept soft-fail … "TLS 1.3 server read_client_finished"` 就是浏览器在收到
  证书后主动断开）。`cert.pem`（9445/9446/853）**完全没有 SAN**，Chrome 连「继续前往」都不给，
  这类访问问题要按证书查，不要按网络查。
