#!/bin/sh
# ECH 端到端演示 + 正确性回归（**临时实例，绝不碰生产**）：
#   1) 用 `--gen-cert` 生成**四张**证书：内层真实 RSA/EC + 外层 cover RSA/EC
#      （不依赖 openssl/bssl）
#   2) 起一个临时 listener（127.0.0.1:18443），按 RFC 9849 配好内/外层
#   3) 三条探针 —— 判据见下
#
# 为什么外层也要 RSA **和** EC 两张（§21.34 的教训）：
#   BoringSSL 按客户端 `signature_algorithms` 在 RSA/EC 证书里选。外层只放一张 RSA 时，
#   一个**只提供 ECDSA** 的非 ECH 客户端就会落回「另一层」的 EC 证书 —— 而那正是内层真实
#   证书 ⇒ 主动探测者换一组 sigalgs 就能把内层逼出来，ECH 白做。所以：
#     探针 ③（只提供 ECDSA + 不带 ECH）拿到的 **必须** 是外层 cover 的指纹。
#
# 演示用的 ECH 物料直接读生产的 state/ech/（只读），不写任何生产文件。
set -u
cd /crucible || exit 9
# 用哪个二进制：默认生产入口；发布前想先验一遍时用
#   BIN=./target/release/webserver sh scripts/ech_demo.sh
BIN=${BIN:-./bin/webserver}
# 探针同理：默认生产入口；发布前先验用 target/release 的那份
# （旧探针不认识 --sigalgs，会在探针 ③ 里静默退化成「不限制 sigalgs」，
#   于是 ③ 与 ② 看起来一样、把真问题掩盖掉 —— 我自己踩过）
PROBE=${PROBE:-./bin/ech_probe}
echo "使用二进制：$BIN   探针：$PROBE"
D=/tmp/echdemo
rm -rf "$D"; mkdir -p "$D/conf" "$D/www"

echo "=== 1) 生成四张证书（--gen-cert，走链接进来的 BoringSSL）==="
# 内层真实（服务 prod.crucible.local）
"$BIN" --gen-cert prod.crucible.local --out-cert "$D/real.pem"    --out-key "$D/real.key.pem"    --days 365 || exit 1
"$BIN" --gen-cert prod.crucible.local --out-cert "$D/real_ec.pem" --out-key "$D/real_ec.key.pem" --days 365 --ec || exit 1
# 外层 cover（覆盖 ech_public_name = crucible.local）
"$BIN" --gen-cert crucible.local      --out-cert "$D/cover.pem"    --out-key "$D/cover.key.pem"    --days 365 || exit 1
"$BIN" --gen-cert crucible.local      --out-cert "$D/cover_ec.pem" --out-key "$D/cover_ec.key.pem" --days 365 --ec || exit 1
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
cert_ec = "$D/real_ec.pem"
key_ec = "$D/real_ec.key.pem"
ech = true
ech_keys = "/crucible/state/ech/ech_keys.pem"
ech_public_name = "crucible.local"
ech_cover_cert = "$D/cover.pem"
ech_cover_key = "$D/cover.key.pem"
ech_cover_cert_ec = "$D/cover_ec.pem"
ech_cover_key_ec = "$D/cover_ec.key.pem"
EOF
echo hi > "$D/www/index.html"
"$BIN" --config "$D/conf/demo.toml" --check-config || exit 1

echo "=== 3) 起临时实例 ==="
"$BIN" --config "$D/conf/demo.toml" > "$D/demo.log" 2>&1 &
PID=$!
sleep 4
if ! kill -0 "$PID" 2>/dev/null; then
	echo "临时实例启动失败："; tail -5 "$D/demo.log"; exit 1
fi
echo "pid=$PID"

ECH=/crucible/state/ech/ech_config_list.bin
echo
echo "=== 4) 探针 ①  ECH 客户端（内层名）→ 必须是内层真实证书 ==="
"$PROBE" 127.0.0.1:18443 "$ECH" prod.crucible.local
echo
echo "=== 5) 探针 ②  非 ECH + RSA sigalgs → 必须是外层 cover ==="
"$PROBE" 127.0.0.1:18443 "$ECH" crucible.local --no-ech
echo
echo "=== 6) 探针 ③  非 ECH + **只提供 ECDSA** → 也必须拿到外层 cover（§21.34 回归）==="
"$PROBE" 127.0.0.1:18443 "$ECH" crucible.local --no-ech --sigalgs ecdsa_secp256r1_sha256
echo
echo "=== 7) 探针 ④（信息性，非判据）非 ECH + **只提供 RSA** ==="
# 本 BoringSSL 的 SSL_CTX_use_certificate 只有**单个** legacy credential 槽（是覆盖语义，
# 不是「按密钥类型各存一张」；多证书要走未导出的 SSL_CREDENTIAL_* API）。所以每层生效的是
# **最后设置的那张**：本用例内外层都配了 EC ⇒ 生效的是 EC。只提供 RSA 的客户端会握手失败，
# 这是该 API 的既有限制，**不是泄漏**（失败 ≠ 拿到内层证书）。这里打印出来是为了让判据
# 保持诚实：不把它当通过条件，也不假装它没发生。
"$PROBE" 127.0.0.1:18443 "$ECH" crucible.local --no-ech --sigalgs rsa_pkcs1_sha256:rsa_pss_rsae_sha256 || true
echo
echo "=== 判据（对照 PEER_SHA256）==="
echo "  ① = 内层真实证书（prod.crucible.local）"
echo "  ②③ 必须 = 外层 cover（crucible.local），且与 ① **不同**"
echo "  这三条是「内外层不共用一张 SSL / 探测者看不出真实域名」的判据；④ 见上（信息性）。"

kill "$PID" 2>/dev/null
echo "=== 清理完成（临时实例已停；生产未受影响）==="