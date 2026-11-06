#!/bin/sh
# 收割「配置已不再引用」的引擎遗留进程与状态目录。
#
# 为什么需要（2026-11-06 真机实测的缺陷）：
#   配置热重载（mtime watcher / SIGHUP）会把**新增/改名**的应用拉起（按 `port-app_idx`
#   生成新的 state key），但**不会关掉**已被移除/改名的旧引擎。实测把 18 条应用从
#   9095 迁到 8443 后：旧 `9095-0` 的 php-fpm master 连同 16 个 pool worker、
#   以及 go/jsp/do/ruby/rack 各一个 sidecar **全部存活**（共 17 个进程），与新
#   `8443-*` 一套并存 —— 进程表被白占、2GB 机器上反复改配置会吃光内存。
#   根因：`reconcile_apps_runtime` 只对**仍在配置里**的 key 做探活/重启
#   （`php::reconcile`），并按 active 集卸载 **dlopen 的 lib**（`app_ffi::reconcile_unload`），
#   唯独没有「按 active 集关停**进程**」这一步 —— 与 lib 的处理不对称。
#   代码级修法见文件末尾注释；本脚本是不改代码就能用的运维兜底。
#
# 判据（三重，宁漏杀不误杀）：
#   1. 扫 `state/native/<key>-<engine>/`、`state/php/<key>/`、`state/go-ipc/<key>/`；
#   2. `<key>` 的 `port-app_idx` 必须**不在**当前 config.toml 的生效集合里（含引擎名归一：
#      `do` 与 `jsp` 是不同应用、不同 idx，各算一个 key）；
#   3. 只杀**能证明**归属该 key 的进程：php-fpm 看命令行里的 conf 绝对路径，
#      sidecar 看 `fstat <该目录下的 sock>` 的持有者。
#
# 用法（目标机 root）：
#   sh scripts/reap-orphan-engines.sh            # 只列出会杀什么（dry-run，默认）
#   sh scripts/reap-orphan-engines.sh --yes      # 真的杀 + 删目录
set -u
ROOT="${CRUCIBLE_ROOT:-/crucible}"
APPLY=0
[ "${1:-}" = "--yes" ] && APPLY=1
cd "$ROOT" || exit 1

# ---- 1) 生效 key 集合：config.toml 里每条 [[listeners]] 的每个 [[listeners.apps]] ----
# 天真的行扫描在这里够用：listener 段落以 `port = N` 定端口，app 段落按出现顺序编号，
# 与运行期 `runtime_key(port, app_idx)` 一致（app_idx 是 `l.apps` 数组下标）。
active=$(awk '
  /^\[\[listeners\]\]$/            { n++; port=""; idx=0; next }
  /^\[\[listeners\.apps\]\]$/      { if (port != "") print port "-" idx; idx++; next }
  /^port[[:space:]]*=/             { if (n>0 && port=="") { v=$0; sub(/^[^=]*=[[:space:]]*/,"",v); port=v } }
' config.toml | sort -u)
[ -z "$active" ] && { echo "没能从 config.toml 解析出生效 key，放弃"; exit 1; }
echo "== 生效 key（config.toml）=="; echo "$active" | tr '\n' ' '; echo

kill_or_show() { # pid
  if [ "$APPLY" = "1" ]; then
    kill -TERM "$1" 2>/dev/null && echo "    TERM $1"
    sleep 1
    ps -p "$1" >/dev/null 2>&1 && kill -9 "$1" 2>/dev/null && echo "    KILL $1"
  else
    echo "    (dry-run) 会杀 pid=$1"
  fi
}

found=0
for d in state/native/*/ state/php/*/ state/go-ipc/*/; do
  [ -d "$d" ] || continue
  key=$(basename "$d" | sed 's/-[a-z0-9]*$//')     # 去掉尾部 `-<engine>`
  # 目录名形如 8443-14-rack；key = 8443-14
  case "$d" in
    state/php/*) key=$(basename "$d") ;;           # php 目录名就是 key
  esac
  # 只认 `<port>-<idx>` 形态；`state/php/tmp` 之类直接跳过
  echo "$key" | grep -qE '^[0-9]+-[0-9]+$' || continue
  echo "$active" | grep -qx "$key" && continue
  found=1
  echo "== 遗留：$d（key=$key 不在配置里）"

  # php-fpm：命令行里带本目录下的 conf 绝对路径
  for pid in $(ps -axo pid,command | grep -F "$ROOT/$d" | grep -vE 'grep|reap-orphan' | awk '{print $1}'); do
    kill_or_show "$pid"
  done
  # sidecar：谁持有本目录下的 sock
  for s in "$d"*.sock "$d"app.sock; do
    [ -e "$s" ] || continue
    for pid in $(fstat "$s" 2>/dev/null | awk 'NR>1 {print $3}' | sort -u); do
      kill_or_show "$pid"
    done
  done
  if [ "$APPLY" = "1" ]; then rm -rf "$d" && echo "    已删除 $d"; fi
done

if [ "$found" = "0" ]; then
  echo "== 没有遗留：所有引擎状态目录都对应当前配置 =="
elif [ "$APPLY" = "0" ]; then
  echo; echo "== 以上为 dry-run。确认无误后重跑：sh $0 --yes =="
fi

# 代码级修法（留给后续）：在 `src/server/apps/mod.rs::reconcile_apps_runtime` 里，
# 遍历 cfg.listeners/l.apps 算出 active key 集后，调用新增的
#   php::reconcile_shutdown(&active_php_keys)            // PHP_RUNTIME 里按 key 关停
#   native_http::reconcile_shutdown(&active_state_dirs)  // SIDECARS（键是 sock 路径）
#   sidecar_engine::reconcile_shutdown(&active_state_dirs) // SIDECARS_SIMPLE
# 与已有的 `app_ffi::reconcile_unload`（lib 按 active 集卸载）对称。关停用
# `child_registry::kill_child`，并同步清掉对应 state 目录。
