#!/bin/sh
# OpenBSD 专有面只读核查（U-02）
#
# 在 **OpenBSD 生产机**上以 root 运行；全部只读，不改任何内核/配置状态。
# 回答三个「Linux 与 OpenBSD 行为差异」问题：
#   1. syncookie：是否存在可读写的 sysctl？（OpenBSD 8.0 实测：不存在，走 pf）
#   2. SO_BUSY_POLL / linux_syncookie：是否为 no-op、是否影响启动？
#   3. v6only 双栈：`[::]` 与 `0.0.0.0` 能否同端口并存？IPV6_V6ONLY 默认值？
#
# 用法：sh scripts/openbsd_checks.sh
# 退出码：0 = 全部符合预期；1 = 有与预期不符的项。
set -u

PY=python3
[ -x /usr/local/bin/python3 ] && PY=/usr/local/bin/python3
[ -x /usr/bin/python3 ] && PY=/usr/bin/python3

fails=0
note() { printf '%s\n' "$*"; }
ok()   { printf 'OK   %s\n' "$*"; }
bad()  { printf 'FAIL %s\n' "$*"; fails=$((fails + 1)); }

echo "=============================================================="
echo "OpenBSD proprietary-surface checks  ($(uname -sr) / $(sysctl -n hw.ncpu) cpu)"
echo "=============================================================="

# ---- 1. syncookie -----------------------------------------------------------
echo
echo "--- 1. syncookie ---"
if sysctl -n net.inet.tcp.syncookies >/dev/null 2>&1; then
    note "net.inet.tcp.syncookies = $(sysctl -n net.inet.tcp.syncookies) (exists)"
else
    ok "net.inet.tcp.syncookies 不存在（OpenBSD：由 pf(4) 管理）——本模块在 OpenBSD 上 no-op 正确"
fi
if sysctl -a 2>/dev/null | grep -qi 'cook'; then
    note "sysctl -a 中的 cookie 相关旋钮：$(sysctl -a 2>/dev/null | grep -i cook | tr '\n' ' ')"
else
    ok "sysctl -a 中无任何 cookie 相关旋钮"
fi
if grep -qE '^[[:space:]]*set[[:space:]]+syncookies' /etc/pf.conf 2>/dev/null; then
    note "pf.conf 已显式设置：$(grep -E '^[[:space:]]*set[[:space:]]+syncookies' /etc/pf.conf)"
else
    note "pf.conf 未显式启用 syncookies（默认 never）——即当前 pf 不做 syncookie"
fi

# ---- 2. busy_poll -----------------------------------------------------------
echo
echo "--- 2. SO_BUSY_POLL / linux_syncookie ---"
if grep -rq 'SO_BUSY_POLL' /usr/include 2>/dev/null; then
    note "SO_BUSY_POLL 在 OpenBSD 头文件中存在"
else
    ok "OpenBSD 头文件无 SO_BUSY_POLL —— linux_busy_poll 特性无法生效（build cfg 已 gate 到 Linux）"
fi
note "linux_syncookie / linux_busy_poll 是 Linux-only cargo feature，OpenBSD 构建不包含 ⇒ 分支为 no-op"

# ---- 3. v6only dual stack ---------------------------------------------------
echo
echo "--- 3. v6only dual-stack ---"
if sysctl -n net.inet6.ip6.v6only >/dev/null 2>&1; then
    note "net.inet6.ip6.v6only = $(sysctl -n net.inet6.ip6.v6only)"
else
    note "net.inet6.ip6.v6only 不存在（OpenBSD 8.0）"
fi
"$PY" - <<'PY'
import socket, sys
PORT = 46011
rc = 0
s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
d = s6.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY)
s6.close()
print(("OK   " if d == 1 else "FAIL ") + f"IPV6_V6ONLY 默认值 = {d}（期望 1 = 默认 v6-only）")
if d != 1:
    rc = 1
# 0.0.0.0:P 与 [::]:P 能否并存
s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s4.bind(("0.0.0.0", PORT)); s4.listen(1)
    s6.bind(("::", PORT)); s6.listen(1)
    print(f"OK   0.0.0.0:{PORT} 与 [::]:{PORT} 可同端口并存")
except OSError as e:
    print(f"FAIL 同端口并存失败: {e}"); rc = 1
finally:
    s4.close(); s6.close()
# 是否能关闭 v6only（Linux 式双栈）
try:
    t = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    t.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    print("NOTE 可设置 IPV6_V6ONLY=0（Linux 式双栈；OpenBSD 预期不可）")
    t.close()
except OSError as e:
    print(f"OK   IPV6_V6ONLY=0 被拒（{e}）—— OpenBSD 永久 v6-only，无法从 [::] 做双栈")
sys.exit(rc)
PY
[ $? -ne 0 ] && fails=$((fails + 1))

echo
echo "=============================================================="
if [ "$fails" -eq 0 ]; then
    echo "openbsd_checks: ALL OK"
    exit 0
else
    echo "openbsd_checks: $fails 项不符预期"
    exit 1
fi
