#!/bin/sh
# 本地 h2 吞吐基准（h2load）：量 **m1 与 m10** 的 req/s，用来给 h2 相关改动做前后对照。
#
# 为什么需要它：h2 侧的收益/退化是**平台相关**的（核多的机器上 syscall 与调度开销占比
# 高，1 vCPU 目标机上不是）。没有统一的量法就会出现「一边说无收益、一边说 +33%」这种
# 互相矛盾的结论（本仓库真实发生过，见 `libs/h2/src/framed_write.rs` 的实测表）。
#
# 依赖：h2load（Ubuntu: `apt-get download nghttp2-client` 后解包，或用系统包管理器装；
# 本机用 `bin/aptlocal.sh install nghttp2-client` + `LD_LIBRARY_PATH` 指定用户级 libev）。
#
# 用法：
#   scripts/bench_h2_local.sh <label> [rounds]
#   URL=https://127.0.0.1:19443/ CONC=50 DUR=5 scripts/bench_h2_local.sh before 3
#
# 起一个最小 h2 目标（自签证书 + 两个 docroot，避免「不同站点 root 相同」被配置校验拦下）：
#   D=$(mktemp -d); mkdir -p $D/{wwwroot,wwwroot2}
#   openssl req -x509 -newkey rsa:2048 -nodes -keyout $D/key.pem -out $D/cert.pem \
#       -days 3650 -subj /CN=localhost
#   head -c 1386 /dev/urandom | base64 > $D/wwwroot/index.html; cp $D/wwwroot/index.html $D/wwwroot2/
#   cat > $D/bench.toml <<'EOF'
#   [[listeners]]
#   address = "127.0.0.1"
#   port = 19443
#   root = "<$D>/wwwroot"
#   server_name = "localhost"
#   http_versions = ["h1", "h2"]
#   [listeners.ssl]
#   cert = "<$D>/cert.pem"
#   key = "<$D>/key.pem"
#   EOF
#   target/release/webserver --config $D/bench.toml &     # 再跑本脚本
# h2c（明文 prior-knowledge）另加一个 listener：同 root 会**被校验拒绝**，用第二个 docroot，
# http_versions = ["h1","h2"]（注意 token 是 `h2`，写 `h2c` 会被判成「h2 被禁用」）。
#
# 起点（2026-11-03，32 核 WSL2 Linux，1.3KB 静态文件，TLS+h2）：
#   coalesce=off: m1 39,750  m10 101,650 req/s
#   coalesce=on : m1 44,411  m10 134,886 req/s   ← 默认值（+11.7% / +32.7%）
set -u

H2LOAD=${H2LOAD:-h2load}
URL=${URL:-https://127.0.0.1:19443/}
LABEL=${1:-run}
ROUNDS=${2:-3}
CONC=${CONC:-50}
THREADS=${THREADS:-$(nproc 2>/dev/null || echo 2)}
DUR=${DUR:-5}

printf '### %s  url=%s conc=%s threads=%s dur=%ss rounds=%s\n' \
	"$LABEL" "$URL" "$CONC" "$THREADS" "$DUR" "$ROUNDS"

for m in 1 10; do
	best=0
	vals=""
	fails=""
	i=1
	while [ "$i" -le "$ROUNDS" ]; do
		out=$($H2LOAD -c "$CONC" -t "$THREADS" -D "$DUR" -m "$m" "$URL" 2>&1)
		r=$(printf '%s\n' "$out" | awk '/^finished in/{gsub(/,/,""); print int($4)}' | tail -1)
		f=$(printf '%s\n' "$out" | awk '/^requests:/{print $0}' | sed -n 's/.*, \([0-9]*\) failed.*/\1/p' | tail -1)
		vals="$vals ${r:-0}"
		fails="$fails ${f:-?}"
		[ "${r:-0}" -gt "$best" ] && best=${r:-0}
		i=$((i + 1))
	done
	med=$(printf '%s\n' $vals | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
	printf 'm%-3s req/s: rounds=[%s ]  best=%s median=%s  failed=[%s ]\n' \
		"$m" "$vals" "$best" "$med" "$fails"
done
