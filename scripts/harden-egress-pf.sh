#!/bin/sh
# 【可选工具，默认**不**部署】按**引擎用户**收敛出网的 pf 规则生成器。
#
# ⚠️ 重要：本脚本是一个**运维可选**的收紧手段，**当前生产部署并未启用**
#    （2026-11-06 实测 `/etc/pf.conf` 里没有本脚本的规则块）。
#
# 背景（含一次真实误读，留作教训）：本项目 spec 要求 53 端口的 DNS 能力
# （root/递归/权威、DoT/DoH、ECS 等），**上游 53 是放开的、是可用能力，不是一个"洞"**。
# 曾把「上游 53 放开」误当漏洞而封掉引擎的 53，等于砍功能 —— 已回滚。
# 因此：**除非运维明确要求收紧，不要运行本脚本**；要收紧也必须把应用真正需要的
# 端口（**含 53**）显式写进放行列表。
#
# 它做什么：给引擎用户（默认 `www` + config.toml 里各应用 `[sandbox] user` 指定的用户）
# 装上三条 quick 规则，插在裸 `pass` **之前**：
#   1. 允许放行端口（默认 80/443/**53**）
#   2. （可选，`--use-local-resolver`）把解析改走本机递归解析器，从而可以不放行 53
#   3. 其余出站 `block return out log quick`（DNS 隧道、任意端口外联、内网横向）
#
# 关键性质：规则**按用户**匹配 ⇒ 不影响 root、`_bind`（named 自身递归）、`_stalwart` 等。
# 幂等：重复运行会先删掉上次插入的块再插一遍。改动前备份，且**先 `pfctl -nf` 干跑解析**，
# 解析不过就不加载（宁可不改也不要把规则集弄坏）。
#
# ⚠️ 换了引擎降权用户（`[listeners.apps.sandbox] user`）后**必须重跑**本脚本，
#    否则新 uid 不在规则里会落回裸 `pass`（= 全出网，等于没装）。
#
# 用法（目标机 root）：
#   sh scripts/harden-egress-pf.sh                 # 装上/刷新规则（默认放行 80,443,53）
#   sh scripts/harden-egress-pf.sh --ports 80,443,53,587
#   sh scripts/harden-egress-pf.sh --remove        # 卸载（回到原状）
#   sh scripts/harden-egress-pf.sh --use-local-resolver
#       把 /etc/resolv.conf 指向本机递归解析器（127.0.0.1）——本机 named 已 `recursion yes`
#       且 `allow-recursion { 127.0.0.1; }`，回环又不受 pf 过滤，所以解析照常，
#       而"引擎直连外部 53"可被完全封掉。**仅在运维明确要封引擎 53 时才用**。
set -u
ROOT="${CRUCIBLE_ROOT:-/crucible}"
PF=/etc/pf.conf
MARK_BEGIN="# BEGIN crucible engine egress"
MARK_END="# END crucible engine egress"
PORTS="80, 443, 53"

USE_LOCAL_RESOLVER=0
case "${1:-}" in
--ports)
	PORTS=$(echo "$2" | tr ',' ', ' | sed 's/,  */, /g')
	;;
--use-local-resolver)
	USE_LOCAL_RESOLVER=1
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
	grep -E '^[[:space:]]*user[[:space:]]*=' "$ROOT/config.toml" 2>/dev/null |
		sed 's/.*=[[:space:]]*//; s/"//g; s/#.*//; s/[[:space:]]//g'
} | grep -vE '^(none|root|-)$' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//')
[ -z "$users" ] && { echo "没找到引擎用户，放弃"; exit 1; }
ulist="{ $(echo "$users" | sed 's/,/, /g') }"
# pfctl 会把用户名渲染成 `user = <uid>`，展示/匹配都要用 uid
uids=$(for x in $(echo "$users" | tr ',' ' '); do id -u "$x" 2>/dev/null; done | tr '\n' '|' | sed 's/|$//')
[ -z "$uids" ] && { echo "无法解析引擎用户 uid，放弃"; exit 1; }

echo "== 引擎用户：$ulist"
echo "== 放行端口：$PORTS"

# ---- DNS 解析路径：决定引擎的 53 是否要放行 ----
ns_list=$(grep -E '^[[:space:]]*nameserver' /etc/resolv.conf 2>/dev/null |
	awk '{print $2}' | grep -vE '^(127\.0\.0\.1|::1|localhost)$' | tr '\n' ',' | sed 's/,$//')
local_ns=0
if grep -qE '^[[:space:]]*nameserver[[:space:]]+(127\.0\.0\.1|::1)' /etc/resolv.conf 2>/dev/null; then
	local_ns=1
fi
if [ "$USE_LOCAL_RESOLVER" = "1" ] && [ "$local_ns" != "1" ]; then
	echo "== 切换解析器到本机 named（127.0.0.1）=="
	# 先确认本机解析器真的能用，否则不切（切了会打断全机解析，含邮件服务）
	if ! dig +short +time=4 +tries=1 @127.0.0.1 example.com >/dev/null 2>&1; then
		echo "!! 本机 127.0.0.1:53 解析失败，放弃切换（保持原解析器）" >&2
	else
		cp -p /etc/resolv.conf "/etc/resolv.conf.bak-$(date +%Y%m%d-%H%M%S)"
		# 保留 `lookup` 等既有指令，只替换 nameserver 行
		grep -vE '^[[:space:]]*nameserver' /etc/resolv.conf > /etc/resolv.conf.new
		echo "nameserver 127.0.0.1" >> /etc/resolv.conf.new
		mv /etc/resolv.conf.new /etc/resolv.conf
		# 校验：改完全机（含引擎用户）还能解析
		if dig +short +time=4 +tries=1 example.com >/dev/null 2>&1; then
			echo "  已切换；校验：解析正常（回滚：cp -p /etc/resolv.conf.bak-* /etc/resolv.conf）"
			local_ns=1
		else
			echo "  !! 切换后解析失败，立即回滚" >&2
			cp -p /etc/resolv.conf.bak-* /etc/resolv.conf 2>/dev/null || true
		fi
	fi
fi
if [ "$local_ns" = "1" ]; then
	DNS_RULE="# 解析走本机递归解析器（回环被 set skip on lo 跳过，无需放行 53）"
else
	# 未切本机解析器：放行到「已配置的解析器」的 53，保证解析不坏。
	ns_set=$(echo "$ns_list" | sed 's/,/, /g')
	DNS_RULE="pass out quick proto { tcp udp } to { $ns_set } port 53 user $ulist"
	echo "  放行到解析器 [$ns_list] 的 53（DNS 是应用功能，默认保留）。"
	echo "        仅当运维明确要求封掉引擎直连 53 时，才加 --use-local-resolver。"
fi

cp -p "$PF" "$PF.bak-$(date +%Y%m%d-%H%M%S)"
# 先删旧块（幂等），再在第一条**裸 `pass`** 之前插入新块
sed "/^${MARK_BEGIN}/,/^${MARK_END}/d" "$PF" > "$PF.tmp"

# 插入锚点：第一条 catch-all `pass`（可能是 `pass`、`pass   # 注释`、`pass all`），
# 若没有，就退回到第一条 `pass out ...`（必须在它**之前**，否则它会把引擎的流量先放走）。
# 两种都没匹配到就报错退出，绝不静默不装规则。
awk -v b="$MARK_BEGIN" -v e="$MARK_END" -v u="$ulist" -v p="$PORTS" -v d="$DNS_RULE" -v pf="$PF" '
	!done && (/^pass[[:space:]]*$/ || /^pass[[:space:]]+#/ || /^pass[[:space:]]+all[[:space:]]*$/ || /^pass out/) {
		print b;
		print "# 引擎会被攻破（见 contact.txt 的威胁模型）：只给它干活必需的出口。";
		print "pass out quick proto { tcp udp } to port { " p " } user " u;
		print d;
		print "block return out log quick proto { tcp udp } user " u;
		print e;
		done = 1;
	}
	{ print }
	END { if (!done) { print "!! 在 " pf " 里找不到插入锚点（catch-all `pass` 或 `pass out`）" > "/dev/stderr"; exit 3 } }
' "$PF.tmp" > "$PF.tmp2"
if [ $? -ne 0 ] || ! grep -q "^${MARK_BEGIN}" "$PF.tmp2"; then
	echo "!! 插入失败，未加载（原配置未动）" >&2
	rm -f "$PF.tmp" "$PF.tmp2"
	exit 1
fi

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
pfctl -s rules 2>/dev/null | grep -B1 -A4 -E "user = ($uids)" | head -16

echo
echo "== 验证（以引擎用户身份实测）=="
u1=$(echo "$users" | cut -d, -f1)
# 探针要挑「对端肯定在监听」的端口，否则分不清「被 pf 拦」和「对端没开」；
# 也不要拿本机自己的公网 IP（自连走 lo，被 `set skip on lo` 跳过 pf，会误判成"通"）。
su -s /bin/sh "$u1" -c 'python3 - <<PY
import socket
def t(h,p,l,expect):
    try:
        s=socket.socket(); s.settimeout(6); s.connect((h,p)); s.close(); r="通"
    except Exception: r="不通"
    flag = "OK" if r==expect else "** 不符 **"
    print("  %-34s %s  (期望%s)  %s" % (l, r, expect, flag))
# 白名单端口：dns.google 的 DoH 走 443，必然开放
t("1.1.1.1",443,"外部 443（白名单）","通")
# 非白名单端口：取「肯定在监听」的端口，才能区分 pf 拦截 与 对端没开
t("1.1.1.1",853,"外部 853 DoT（非白名单）","不通")
t("8.8.8.8",53,"外部 DNS 53（非白名单）","不通")
# 解析必须仍然可用（已切到本机递归解析器，走回环）
try:
    print("  域名解析 example.com ->", socket.gethostbyname("example.com"))
    print("  域名解析 www.wikipedia.org ->", socket.gethostbyname("www.wikipedia.org"))
except Exception as e:
    print("  ** 域名解析失败：", e, "**")
PY' 2>&1 | tail -8

echo
echo "== 规则命中计数（略等几秒后看计数器）=="
pfctl -s rules -v 2>/dev/null | grep -A1 -E "user = ($uids)" | head -20
echo
echo "== 收尾 =="
echo "备份：ls $PF.bak-*"
echo "回滚：sh $0 --remove"
