#!/bin/sh
# 为**每个应用**创建独立非特权用户，使「一个引擎被攻破」看不到另一个引擎的数据。
#
# 为什么需要：默认所有引擎共用 `www`（见 sandbox.rs 的 `default_drop_user`）。共用带来的
# 问题不是"能拿下主机"（那已经挡住：非 root + unveil + pledge + 宿主机密钥 640），而是
# **应用之间可互读** —— app A 的 socket/日志/上传目录，app B 的用户也能读。
# 要做到应用级隔离，就给不同应用配不同的用户：
#
#   [[listeners.apps]]
#   ... engine = "php" ...
#   [listeners.apps.sandbox]
#   user = "_c_php"
#
# 本脚本按给定名单创建这些用户（幂等）。OpenBSD 用 `useradd`；Linux 用 `useradd -r`。
#
# 用法（目标机 root）：
#   sh scripts/create-engine-users.sh _c_php _c_ruby _c_node
#   sh scripts/create-engine-users.sh --from-config       # 从 config.toml 里扫 [sandbox] user
set -u
ROOT="${CRUCIBLE_ROOT:-/crucible}"
OS=$(uname -s)

users=""
if [ "${1:-}" = "--from-config" ]; then
	# 扫描配置里显式写了的 user（排除 www/none/root）
	users=$(grep -E '^\s*user\s*=' "$ROOT/config.toml" 2>/dev/null |
		sed 's/.*=\s*//; s/"//g; s/#.*//' |
		grep -vE '^(www|nobody|none|root|-)$' | sort -u)
else
	users="$*"
fi
[ -z "$users" ] && { echo "没有要创建的用户（用法见文件头）"; exit 0; }

echo "== 要创建/确认的引擎用户：$users =="
for u in $users; do
	if id "$u" >/dev/null 2>&1; then
		echo "  $u 已存在（$(id "$u")）"
		continue
	fi
	case "$OS" in
	OpenBSD) useradd -s /sbin/nologin -d /nonexistent -c "crucible app engine" "$u" ;;
	*) useradd -r -s /sbin/nologin -d /nonexistent -c "crucible app engine" "$u" 2>/dev/null ||
		adduser --system --no-create-home --shell /sbin/nologin "$u" ;;
	esac
	if id "$u" >/dev/null 2>&1; then
		echo "  已创建 $u（$(id "$u")）"
	else
		echo "  !! 创建 $u 失败" >&2
	fi
done
echo "完成。把上面对应的 user 写进各应用的 [listeners.apps.sandbox] user = \"<名>\" 后重启即可生效。"
