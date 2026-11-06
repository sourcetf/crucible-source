#!/bin/sh
# 按**引擎用户**收敛出网（OpenBSD pf）：给"会被攻破的"引擎进程只留它干活必需的出口。
#
# 为什么需要（现状实测 2026-11-06）：`/etc/pf.conf` 只有一条裸 `pass` —— 全出站放开，
# 仅限制了 `_pbuild`。以引擎用户 `www` 身份实测可达：外部 DNS 53、外部 443、
# **本机 SSH 22**（拿别的服务当跳板）。用户也指出 **上游 53 是放开的** —— 也就是说
# 被 RCE 的引擎可以直接把数据编码进 DNS 查询发到任意解析器，或直接连本机服务。
#
# 本脚本给引擎用户（默认 `www` + config.toml 里各应用 `[sandbox] user` 指定的用户）
# 装上三条 quick 规则，插在裸 `pass` **之前**：
#   1. 允许 80/443（web 应用调用外部 API 的刚需）
#   2. 允许 53（解析走本机递归解析器；回环已被 `set skip on lo` 跳过，这条只管非回环）
#   3. 其余出站一律 `block return out log quick`（DNS 隧道、SMTP、任意端口外联、内网横向）
#
# 关键性质：规则**按用户**匹配 ⇒ 不影响 root、_bind、_stalwart 等其它服务。
# 幂等：重复运行会先删掉上次插入的块再插一遍。改动前备份，且**先 `pfctl -nf` 干跑解析**，
# 解析不过就不加载（宁可不改也不要把规则集弄坏）。
#
# 用法（目标机 root）：
#   sh scripts/harden-egress-pf.sh                 # 装上/刷新规则
#   sh scripts/harden-egress-pf.sh --ports 80,443,8080   # 自定义放行端口
#   sh scripts/harden-egress-pf.sh --remove        # 卸载（回到原状）
set -u
ROOT="${CRUCIBLE_ROOT:-/crucible}"
PF=/etc/pf.conf
MARK_BEGIN="# BEGIN crucible engine egress"
MARK_END="# END crucible engine egress"
PORTS="80, 443"

case "${1:-}" in
--ports)
	PORTS=$(echo "$2" | tr ',' ', ' | sed 's/,  */, /g')
	;;
--remove)
	echo "== 卸载引擎出网规则 =="
	cp -p "$PF" "$PF.bak-$(date +%Y%m%d-%H%M%S)"
	sed "/^${MARK_BEGIN}/,/^${MARK_END}/d" "$PF" > "$PF.tmp" && mv "$PF.tmp" "$PF"
	if pfctl -nf "$PF" 2>/dev/null; then
		pfctl -f "$PF"
		echo "已卸载并重新加载"
	else
		echo "!! 解析失败，未加载（$PF 已改，请检查）" >&2
		exit 1
	fi
	exit 0
	;;
esac

# 引擎用户名单：www + 各应用显式配的 user（排除 none/root）
users=$( { echo www
	grep -E '^\s*user\s*=' "$ROOT/config.toml" 2>/dev/null |
		sed 's/.*=\s*//; s/"//g; s/#.*//; s/ //g'
} | grep -vE '^(none|root|-|)$' | sort -u | tr '\n' ',' | sed 's/,$//')
[ -z "$users" ] && { echo "没找到引擎用户，放弃"; exit 1; }
ulist="{ $(echo "$users" | sed 's/,/, /g') }"

echo "== 引擎用户：$ulist"
echo "== 放行端口：$PORTS"

cp -p "$PF" "$PF.bak-$(date +%Y%m%d-%H%M%S)"
# 先删旧块（幂等），再在第一条**裸 `pass`** 之前插入新块
sed "/^${MARK_BEGIN}/,/^${MARK_END}/d" "$PF" > "$PF.tmp"

awk -v b="$MARK_BEGIN" -v e="$MARK_END" -v u="$ulist" -v p="$PORTS" '
	!done && /^pass[[:space:]]*$/ {
		print b;
		print "# 引擎会被攻破（见 contact.txt 的威胁模型）：只给它干活必需的出口。";
		print "pass out quick proto { tcp udp } to port { " p " } user " u;
		print "pass out quick proto { tcp udp } to port 53 user " u;
		print "block return out log quick proto { tcp udp } user " u;
		print e;
		done = 1;
	}
	{ print }
' "$PF.tmp" > "$PF.tmp2"

# **先干跑解析**：解析不过就不动线上规则集。
if ! pfctl -nf "$PF.tmp2" 2>"$PF.parseerr"; then
	echo "!! 规则解析失败，未加载（原配置未动）：" >&2
	cat "$PF.parseerr" >&2
	rm -f "$PF.tmp" "$PF.tmp2" "$PF.parseerr"
	exit 1
fi
mv "$PF.tmp2" "$PF"
rm -f "$PF.tmp" "$PF.parseerr"
pfctl -f "$PF"
echo "== 已加载。当前引擎相关规则： =="
pfctl -s rules 2>/dev/null | grep -A4 -B1 "user $ulist" | head -12

echo
echo "== 验证（以引擎用户身份）=="
u1=$(echo "$users" | cut -d, -f1)
su -s /bin/sh "$u1" -c 'python3 - <<PY
import socket
def t(h,p,l):
    try:
        s=socket.socket(); s.settimeout(4); s.connect((h,p)); s.close(); print(f"  {l}: 通")
    except Exception: print(f"  {l}: 不通")
t("1.1.1.1",443,"外部 443（应通）")
t("8.8.8.8",53,"外部 DNS 53（应不通）")
t("127.0.0.1",53,"本机解析器（应通：lo 被 skip）")
t("83.229.125.81",22,"本机 SSH 22（应不通）")
PY' 2>&1 | tail -6
