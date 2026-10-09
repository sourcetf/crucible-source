#!/bin/sh
# accept-verify-stop.sh — 停掉工号 1009 / agent-verify2 验收实例。
SCRATCH=/home/dev123/scratch-verify4
PIDF=$SCRATCH/webserver.pid
if [ -f "$PIDF" ]; then
  OLD=$(cat "$PIDF" 2>/dev/null || true)
  if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then kill "$OLD" 2>/dev/null || true; fi
  rm -f "$PIDF"
fi
pkill -f "webserver --config $SCRATCH/conf/config-verify.toml" 2>/dev/null || true
echo "stopped"
