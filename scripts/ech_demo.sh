#!/bin/sh
# ECH 端到端演示（**临时实例，绝不碰生产**）：
#   1) 用 `--gen-cert` 生成外层 cover 与内层真实两张证书（不依赖 openssl/bssl）
#   2) 起一个临时 listener（127.0.0.1:18443），按 RFC 9849 配好内/外层
#   3) 两条探针：ECH 客户端必须拿到**内层真实证书**；非 ECH 客户端只能拿到**外层 cover**
#
# 演示用的 ECH 物料直接读生产的 state/ech/（只读），不写任何生产文件。
set -u
cd /crucible || exit 9
D=/tmp/echdemo
rm -rf "$D"; mkdir -p "$D/conf" "$D/www"

echo "=== 1) 生成两张证书（--gen-cert，走链接进来的 BoringSSL）==="
./bin/webserver --gen-cert crucible.local      --out-cert "$D/cover.pem" --out-key "$D/cover.key.pem" --days 365 || exit 1
./bin/webserver --gen-cert prod.crucible.local --out-cert "$D/real.pem"  --out-key "$D/real.key.pem"  --days 365 || exit 1
ls -l "$D"/*.pem

echo "=== 2) 临时 listener 配置（127.0.0.1:18443）==="
# 注意：`ech_keys` 用**绝对路径** —— 相对路径按**配置目录**解析（C-13 后的语义），
# 演示配置在 /tmp/echdemo，所以相对写法的 state/ech/... 会找不到。
cat > "$D/conf/demo.toml" <<EOF
[[listeners]]
address = "127.0.0.1"
port = 18443
root = "$D/www"
http_versions = ["h1", "h2"]
server_name = "prod.crucible.local"

[listeners.ssl]
cert = "$D/real.pem"
key = "$D/real.key.pem"
ech = true
ech_keys = "/crucible/state/ech/ech_keys.pem"
ech_public_name = "crucible.local"
ech_cover_cert = "$D/cover.pem"
ech_cover_key = "$D/cover.key.pem"
EOF
echo hi > "$D/www/index.html"
./bin/webserver --config "$D/conf/demo.toml" --check-config || exit 1

echo "=== 3) 起临时实例 ==="
./bin/webserver --config "$D/conf/demo.toml" > "$D/demo.log" 2>&1 &
PID=$!
sleep 4
if ! kill -0 "$PID" 2>/dev/null; then
	echo "临时实例启动失败："; tail -5 "$D/demo.log"; exit 1
fi
echo "pid=$PID"

echo "=== 4) ECH 客户端（内层名 prod.crucible.local）==="
./bin/ech_probe 127.0.0.1:18443 /crucible/state/ech/ech_config_list.bin prod.crucible.local

echo "=== 5) 非 ECH 客户端（外层名 crucible.local，= 探测者视角）==="
./bin/ech_probe 127.0.0.1:18443 /crucible/state/ech/ech_config_list.bin crucible.local --no-ech

kill "$PID" 2>/dev/null
echo "=== 清理完成（临时实例已停；生产未受影响）==="
