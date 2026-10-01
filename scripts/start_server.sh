#!/bin/sh
# 启动 Crucible webserver —— **委托给 /etc/rc.local**（安装自 scripts/deploy/rc.local）。
#
# 为什么改成委托：
#  1. 启动方式只能有一份。以前这里自己写了一套 `pkill -f target/release/webserver`
#     + `nohup ./target/release/webserver`，而生产入口其实是 `/crucible/bin/webserver`
#     ⇒「重启」等于起第二个实例（抢不到端口后自己退出）或停不掉旧实例，运维以为换了新二进制；
#     日志也写到 `/tmp/webserver-restart.log`，而轮转钩子（daily.local）只管
#     `/var/log/crucible-restart.log` ⇒ 那份 /tmp 日志没有任何上限（本机 /tmp 常是 mfs 内存盘）。
#  2. 证书/ECH 材料**不再用 openssl 现生成**（本项目明确不依赖 openssl）：
#     缺材料就让 rc.local 起不来 → webserver 自己会在启动日志里报出来；
#     需要生成材料请走面板/ACME，或准备好文件后再启动。
set -e
cd /crucible

if [ ! -f /etc/rc.local ]; then
	echo "start_server: /etc/rc.local 不存在；请先 cp scripts/deploy/rc.local /etc/rc.local 并 chmod 755" >&2
	exit 1
fi

# 缺 TLS 材料时**只提醒不代劳**：以前用 openssl 静默生成（依赖本项目不该依赖的工具），
# 且失败被 `|| true` 吞掉，结果是一个没有证书的端口。
for f in cert.pem key.pem; do
	if [ ! -f "/crucible/$f" ]; then
		echo "start_server: 缺少 /crucible/$f —— 请准备好证书材料（面板/ACME/手工放置）后再启动" >&2
		exit 1
	fi
done

sh /etc/rc.local
