#!/bin/sh
# 收紧**宿主自己的密钥/配置**权限，使降权后的引擎用户（默认 www）读不到。
#
# 为什么单独一个脚本：这份权限不是沙箱配置能覆盖的 —— 引擎以非特权用户运行后，
# 决定它能读到什么的**首先**是文件模式。实测（2026-11-06）目标机上
#   /crucible/config.toml   -rw-r--r--   含 admin 的 argon2 password_hash
#   /crucible/key.pem       -rw-r--r--   服务器 TLS 私钥
#   /crucible/key_ec.pem    -rw-r--r--   同上（ECC 副证）
# 都是 644 ⇒ 任何以 www 身份运行的进程（= 任何一个被 RCE 的引擎）都能读走
# 管理员密码哈希与服务器私钥。unveil 在 OpenBSD 上能挡住路径（这些路径未揭示），
# 但**文件模式是跨平台、且在 unveil 失效时仍生效的那一层**，必须一起收。
#
# 幂等：重复运行无副作用。用法（在目标机上，root）：
#   sh scripts/harden-secret-perms.sh [<engine_user>]
set -u
ROOT="${CRUCIBLE_ROOT:-/crucible}"
USER_="${1:-www}"
cd "$ROOT" 2>/dev/null || { echo "找不到 $ROOT"; exit 1; }

echo "== 收紧密钥/配置：owner=root，mode=640（组 ${USER_} 也读不到；只留 root）=="
n=0
for f in config.toml config-test.toml key.pem key_ec.pem cert.pem cert_ec.pem; do
	[ -e "$f" ] || continue
	# 640 root:<wheel 或 root 的组>：引擎用户 www 的组是 www，故读不到。
	chown root:wheel "$f" 2>/dev/null || true
	chmod 640 "$f"
	echo "  $f -> $(ls -l "$f" | awk '{print $1, $3, $4}')"
	n=$((n + 1))
done

echo "== state 下的密钥（ECH/DoT/DNSSEC）=="
find "$ROOT/state" -type f \( -name '*.key' -o -name '*.pem' -o -name '*.private' \) 2>/dev/null |
	while read -r f; do
		case "$f" in
		*cover.pem|*cert*.pem) chmod 640 "$f" 2>/dev/null || true ;; # 证书可公开，防误写即可
		*) chmod 600 "$f" 2>/dev/null || true ;;
		esac
	done
echo "  (完成)"

echo "== 校验：以引擎用户身份尝试读取（必须全部被拒）=="
bad=0
for f in config.toml key.pem key_ec.pem; do
	[ -e "$f" ] || continue
	if su -s /bin/sh "$USER_" -c "head -c1 '$ROOT/$f' >/dev/null 2>&1" 2>/dev/null; then
		echo "  !! $USER_ 仍可读 $f —— 权限没生效"
		bad=$((bad + 1))
	else
		echo "  ok: $USER_ 读不到 $f"
	fi
done
[ "$bad" -eq 0 ] && echo "密钥权限收紧完成（$n 个文件）" || { echo "有 $bad 个文件仍可被引擎用户读取"; exit 1; }
