#!/bin/sh
# accept-verify-stop.sh — 停掉工号 1009 验收实例。
PIDF=/home/dev123/scratch-verify/webserver.pid
if [ -f "$PIDF" ]; then
  OLD=$(cat "$PIDF" 2>/dev/null || true)
  if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then kill "$OLD" 2>/dev/null || true; fi
  rm -f "$PIDF"
fi
pkill -f "webserver --config /home/dev123/scratch-verify/conf/config-verify.toml" 2>/dev/null || true
echo "stopped"
