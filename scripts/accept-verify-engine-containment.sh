#!/bin/sh
# 验收：**假定引擎已被攻破**，验证它拿不下主机（"攻破了依然不威胁到主机器"）。
#
# 威胁模型（2026-11 更新的口径）：应用引擎本身的安全性无法保证 —— PHP/Java/Node/Go
# 运行时在接连出 RCE（PHP CVE-2026-109619/109618、php-fpm CVE-2026-91768、Linux 侧
# CVE-2026-98432 等）。因此验收不看"引擎有没有洞"，只看**洞被打穿之后**攻击者能做什么：
#
#   1. 引擎进程必须是**非特权用户**（不是 root）；
#   2. 以该用户身份：读不到管理员哈希/服务器私钥/系统密码库；
#   3. 写不了系统目录；绑不了特权端口；杀不掉别人的进程。
#
# 判据是"必须被拒"——任何一条"可做"都是失败（fail-closed 验收）。
#
# 用法（目标机 root）：sh scripts/accept-verify-engine-containment.sh [<engine_user>]
set -u
USER_="${1:-www}"
ROOT="${CRUCIBLE_ROOT:-/crucible}"
# 应用自 2026-11-06 起只在 TLS 口（8443）提供；本脚本只按 uid/socket 判据工作，
# 保留该变量仅为可读性（不参与判据）。
PORT="${CRUCIBLE_PORT:-8443}"
fails=0
note() { printf '%-46s %s\n' "$1" "$2"; }
ok() { note "$1" "ok"; }
bad() {
	note "$1" "**FAIL**"
	fails=$((fails + 1))
}

echo "===== 1) 引擎进程身份（必须非 root）====="
for pat in "php-fpm" "ruby34" "java -jar" "go-shm-server" "deps/bin/index" "node"; do
	pids=$(pgrep -f "$pat" 2>/dev/null | head -3)
	[ -z "$pids" ] && continue
	for p in $pids; do
		u=$(ps -o user= -p "$p" 2>/dev/null | tr -d ' ')
		[ -z "$u" ] && continue
		if [ "$u" = "root" ]; then
			bad "进程 $pat (pid $p) 以 root 运行"
		else
			ok "进程 $pat (pid $p) 身份=$u"
		fi
	done
done

echo
echo "===== 2) 以引擎用户身份试读宿主秘密（必须全被拒）====="
t() {
	# t <描述> <命令>：命令成功(=0) => 说明"可做" => 失败
	if su -s /bin/sh "$USER_" -c "$2" >/dev/null 2>&1; then
		bad "$1"
	else
		ok "$1"
	fi
}
t "读系统密码库 /etc/master.passwd" "head -1 /etc/master.passwd"
t "读管理员哈希（config.toml）" "head -1 $ROOT/config.toml"
t "读服务器私钥 key.pem" "head -1 $ROOT/key.pem"
t "读 ECH 私钥 cover.key.pem" "head -1 $ROOT/state/ech/cover.key.pem"
t "读 /root 目录" "ls /root"
t "写 /etc" "touch /etc/.crucible_pwn"
t "读其它应用的 docroot（jsp 的 jar 目录写权限）" "touch $ROOT/libs/jsp-sidecar/target/.pwn"
t "向 pid 1 发信号" "kill -0 1"
t "绑特权端口 80" "python3 -c 'import socket;s=socket.socket();s.bind((\"0.0.0.0\",80))'"

echo
echo "===== 3) 沙箱日志：uid/gid 必须已设置 ====="
if [ -f /var/log/crucible-restart.log ]; then
	n=$(grep -c "uid=Some" /var/log/crucible-restart.log 2>/dev/null || echo 0)
	if [ "$n" -gt 0 ]; then ok "沙箱日志里有 $n 条带 uid=Some(...) 的策略行"; else bad "沙箱日志里没有降权记录（uid=None？）"; fi
fi

echo
if [ "$fails" -eq 0 ]; then
	echo "== CONTAINMENT OK：攻破任一引擎也拿不到主机 =="
	exit 0
fi
echo "== CONTAINMENT FAILED：$fails 项未达标 =="
exit 1
