#!/usr/bin/env bash
# Bench all application engines via wrk (non-std port 19095).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${CRUCIBLE_TEST_PORT:-19095}"
DURATION="${BENCH_DURATION:-3s}"

echo "bench_app_engines: port=${PORT} duration=${DURATION}"
python3 bench/app_engine_overhead.py \
  --port "${PORT}" \
  --duration "${DURATION}" \
  --engines static,rust,c,go,lua,php,python,ruby,perl,wsgi,asgi,asp
