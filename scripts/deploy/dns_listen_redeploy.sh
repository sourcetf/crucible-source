#!/bin/sh
# 部署 named listen-on 修复：预检 → 停（webserver + named）→ 换 → 起 → 复验
# 关键点：**必须显式杀掉 named**。reconcile 只判「named 活着与否」，
# 上一版配置下 named 是「活着的」，所以只重启 webserver 会让 named 继续用旧的
# loopback-only 绑定（这正是我第一次重启后 fstat 仍只有 127.0.0.1:53 的原因）。
set -u
cd /crucible || exit 1
STAMP=`date +%Y%m%d-%H%M%S`

echo "== 1) 快照（二进制 + named.conf）=="
cp -p bin/webserver bin/webserver.bak-$STAMP
cp -p state/dns/etc/named.conf state/dns/etc/named.conf.bak-$STAMP
echo "backup stamp: $STAMP"

echo "== 2) 预检（新二进制 x 生产配置，不绑端口）=="
./target/release/webserver --config /crucible/config.toml --check-config
RC=$?
echo "CHECK_RC=$RC"
if [ "$RC" -ne 0 ]; then echo "!! 预检失败，放弃部署（生产未动）"; exit 1; fi

echo "== 3) 停 webserver + named =="
kill `pgrep -x webserver` 2>/dev/null
sleep 2
kill `pgrep -x named` 2>/dev/null
sleep 2
pgrep -x webserver >/dev/null && echo "WARN webserver 仍在运行" || echo "webserver stopped"
pgrep -x named >/dev/null && echo "WARN named 仍在运行" || echo "named stopped"

echo "== 4) 换二进制 =="
cp -p target/release/webserver bin/webserver

echo "== 5) 启动 =="
sh /etc/rc.local
sleep 10

echo "== 6) 复验 =="
echo "-- 生成的 listen-on:"
grep -n 'listen-on' state/dns/etc/named.conf
echo "-- named-checkconf -z:"
named-checkconf -z state/dns/etc/named.conf && echo "named-checkconf OK"
pgrep -x webserver >/dev/null && echo "webserver: up" || echo "webserver: DOWN"
NP=`pgrep -x named | head -1`
echo "named pid=$NP"
echo "-- named 持有的 53 socket（关键：必须有 83.229.125.81:53）:"
fstat -p "$NP" 2>/dev/null | grep -E 'internet.*:53'
echo "== DONE =="