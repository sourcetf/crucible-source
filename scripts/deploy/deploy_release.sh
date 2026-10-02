#!/bin/sh
# 通用发布流程（在**生产机**上跑）：预检 → 快照 → 停 → 换 → 起 → 复验。
#
# 为什么要有这个脚本（审计 C-22 / C-23）：
#   仓库里曾有的部署脚本是「把工作副本整包上传 → 在生产机上 rm -rf 后重建」，既会
#   把 .git/证书/state 一起传上去，也会一次误运行清空生产源码树；重启时还打错进程名。
#   这里把发布拆成可评审的固定步骤，且**每一步都可回退**（快照在前，换在后）。
#
# 与 dns_listen_redeploy.sh 的分工：
#   - 本脚本：普通代码发布，只重启 webserver。
#   - dns_listen_redeploy.sh：改动涉及 DNS / 监听地址时用，它**额外显式重启 named**
#     （因为 reconcile 只判「named 活着与否」，旧配置下 named 是活着的，不会重建 socket）。
#
# 用法：
#   sh scripts/deploy/deploy_release.sh            # 用已构建好的 target/release/webserver
#   sh scripts/deploy/deploy_release.sh --build    # 先构建再发布
set -u
cd /crucible || exit 1

FEATURES='tls,tls_boring,go_shm_ipc,tls_nss,tls_tomcrypt'
NEW=target/release/webserver
LIVE=bin/webserver
CFG=/crucible/config.toml
STAMP=`date +%Y%m%d-%H%M%S`

if [ "${1:-}" = "--build" ]; then
	echo "== 0) 构建 =="
	cargo build --release --features "$FEATURES" || { echo "!! 构建失败，生产未动"; exit 1; }
fi

if [ ! -f "$NEW" ]; then
	echo "!! 找不到 $NEW —— 先构建：sh scripts/deploy/deploy_release.sh --build"
	exit 1
fi

echo "== 1) 快照（二进制 + 配置）=="
cp -p "$LIVE" "$LIVE.bak-$STAMP" 2>/dev/null || echo "（还没有 $LIVE，跳过）"
cp -p "$CFG"  "$CFG.bak-$STAMP"
echo "backup stamp: $STAMP"

echo "== 2) 预检：新二进制 × 生产配置（只加载+校验，不绑端口）=="
"$NEW" --config "$CFG" --check-config
RC=$?
echo "CHECK_RC=$RC"
if [ "$RC" -ne 0 ]; then
	echo "!! 预检失败，放弃发布（生产未动，仍跑旧二进制）"
	echo "   回退：本次未做任何替换，无需回滚"
	exit 1
fi

echo "== 3) 停 webserver =="
kill `pgrep -x webserver` 2>/dev/null
sleep 2
if pgrep -x webserver >/dev/null; then
	echo "!! webserver 仍在运行，放弃替换（避免出现新旧两个实例）"
	exit 1
fi
echo "webserver stopped"

echo "== 4) 换二进制（同一目录内改名，避免半截文件被 exec）=="
cp -p "$NEW" "$LIVE.new-$STAMP"
mv -f "$LIVE.new-$STAMP" "$LIVE"

echo "== 5) 启动 =="
sh /etc/rc.local
sleep 8

echo "== 6) 复验 =="
pgrep -x webserver >/dev/null && echo "webserver: up" || { echo "webserver: DOWN"; exit 1; }
echo "-- 监听端口:"
netstat -ln -f inet | grep -E '\.(8443|9095|9081|9445|9446|853|53) ' || true
echo "-- h1 探活:"
curl -s -o /dev/null -w '  9095=%{http_code}\n' http://127.0.0.1:9095/
echo "-- h3 探活:"
curl -sk --http3-only -o /dev/null -w '  8443=%{http_code}\n' https://127.0.0.1:8443/ 2>/dev/null || echo "  （本机无 http3 客户端，跳过）"

echo
echo "== DONE =="
echo "回退：cp -p $LIVE.bak-$STAMP $LIVE; kill \$(pgrep -x webserver); sleep 2; sh /etc/rc.local"
echo "若本次改动涉及 DNS/监听地址，请改用 scripts/deploy/dns_listen_redeploy.sh 重发一次"