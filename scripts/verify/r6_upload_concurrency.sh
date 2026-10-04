#!/bin/sh
# 第 6 轮并发报告 #5：**并发同路径「全量上传」**。
#
# 修复前实测：2×201 + 1×409 + 1×500，且**只有一方**的字节落盘（另一方 201 却静默丢数据）。
# 根因：并发闸门只看 `received() > 0`，两个**还没写任何字节**的请求会共享同一个会话与
# `.part`；最后一个 commit 把 `.part` rename 走，另一个 append 撞 Io(No such file)。
#
# 判据：
#   U-a  恰好 1 个 201（不能有 2 个 201 —— 那是两方都以为成功）
#   U-b  其余全是 409（**不得出现 500**，那是内部错误被暴露出来）
#   U-c  落盘文件是**单一来源**（未混写）
#   U-d  没有 `.part` 残留
#
# 用法： R6_TLS=https://127.0.0.1:18443 sh scripts/verify/r6_upload_concurrency.sh
# 前置：该 TLS listener 的 root 下可写（默认取仓库 www/）。
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
B="${R6_TLS:-https://127.0.0.1:18443}"
DOC="${R6_DOCROOT:-$ROOT/www}"
T="$DOC/r6up.bin"; P="$DOC/.r6up.bin.upload.part"
pass=0; fail=0
chk() { if [ "$2" = "0" ]; then echo "PASS  $1"; pass=$((pass+1));
        else echo "FAIL  $1 :: $3"; fail=$((fail+1)); fi; }
cleanup() { rm -f "$T" "$P" /tmp/r6pay_*.bin /tmp/r6codes.txt; }
trap cleanup EXIT INT TERM

rm -f "$T" "$P" /tmp/r6pay_*.bin /tmp/r6codes.txt
for c in a b c d; do
  python3 -c "open('/tmp/r6pay_$c.bin','wb').write(b'$c'*65536)"
done
for c in a b c d; do
  ( curl -sk -m 30 -o /dev/null -w "%{http_code}\n" -T /tmp/r6pay_$c.bin "$B/r6up.bin" >> /tmp/r6codes.txt ) &
done
wait
echo "--- HTTP 码分布 ---"; sort /tmp/r6codes.txt | uniq -c
n201=$(grep -c '^201$' /tmp/r6codes.txt)
n409=$(grep -c '^409$' /tmp/r6codes.txt)
n5xx=$(grep -cE '^5' /tmp/r6codes.txt)
[ "$((n201))" = "1" ]; chk "U-a 恰好 1 个 201（实得 $n201）" $? "n201=$n201"
[ "$((n5xx))" = "0" ]; chk "U-b 无 5xx（实得 $n5xx）" $? "$(sort /tmp/r6codes.txt|uniq -c|tr '\n' ' ')"
[ "$((n201))" = "1" ] && [ "$((n409))" = "3" ]; chk "U-b2 其余 3 个为 409（实得 $n409）" $? "n409=$n409"
python3 - "$T" <<'PY'
import collections, sys
try:
    d = open(sys.argv[1], 'rb').read()
except FileNotFoundError:
    print('落盘文件不存在'); sys.exit(1)
c = collections.Counter(d)
print('大小=%d 来源数=%d' % (len(d), len(c)))
sys.exit(0 if len(c) == 1 and len(d) == 65536 else 1)
PY
chk "U-c 落盘为单一来源且长度正确" $? ""
[ ! -e "$P" ]; chk "U-d 无 .part 残留" $? ""
echo; echo "==== 汇总: PASS=$pass FAIL=$fail ===="
[ "$fail" = "0" ]
