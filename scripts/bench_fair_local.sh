#!/bin/sh
# 本地公平基准：crucible vs h2o（双门禁）。
# 用法: sh scripts/bench_fair_local.sh [duration]
# 前置: crucible 在 9081(plain)/9445(tls12)/9446(tls13)；h2o 在 9082/9447/9448。
set -u
D="${1:-10}"
cd /crucible || exit 1
export PATH=/usr/local/bin:/usr/bin:/bin:$PATH

echo "### 1) 明文 h1：ours :9081 vs h2o :9082"
python3 bench/h2_fair_gate.py --target http://127.0.0.1:9081/ --baseline http://127.0.0.1:9082/ --duration "$D"
echo
echo "### 2) TLS1.3 h1：ours :9446 vs h2o :9447"
python3 bench/h2_fair_gate.py --target https://127.0.0.1:9446/ --baseline https://127.0.0.1:9447/ --duration "$D"
echo
echo "### 3) TLS1.2 h1：ours :9445 vs h2o :9448"
python3 bench/h2_fair_gate.py --target https://127.0.0.1:9445/ --baseline https://127.0.0.1:9448/ --duration "$D"
