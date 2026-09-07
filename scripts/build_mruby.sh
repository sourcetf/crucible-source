#!/bin/sh
# Build mruby static lib for scriptffi (optional). OpenBSD/Linux.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/target/tls-libs/mruby"
mkdir -p "$OUT"
if [ -f "$OUT/lib/libmruby.a" ]; then
  echo "mruby: already built"
  exit 0
fi
echo "mruby: fetch optional — scriptffi falls back to MRI/python/perl embed or popen"
# Placeholder: full mruby clone is large; production builds may vendor separately.
mkdir -p "$OUT/include"
cat > "$OUT/include/mruby.h" <<'EOF'
/* stub header so configure can probe; real mruby replaces this tree */
#ifndef CRUCIBLE_MRUBY_STUB
#define CRUCIBLE_MRUBY_STUB 1
#endif
EOF
echo "mruby: stub headers at $OUT (replace with real mruby for embed)"
