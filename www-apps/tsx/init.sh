#!/bin/sh
# TSX 应用依赖：把 TypeScript/TSX 转译器装进 deps/（项目标准机制：§7.9）。
#
# 为什么装在 deps/：`apps::deps` 会在 init.sh/.env 变化时**清空重建** deps/，
# 所以任何手工装在别处的包都会在下次重建时消失（实测：手工 npm install 的 esbuild
# 被 deps wipe 掉，/tsx/ 于是回落到 npx 联网下载并挂到编译超时）。
# 引擎侧探测顺序：PATH → source/docroot 的 node_modules/.bin → **deps/node_modules/.bin**。
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
DEPS="${DEPS_DIR:-$ROOT/deps}"
mkdir -p "$DEPS"

# 已有可用的全局转译器就**不要**再联网装一份：init.sh 跑在请求路径的 deps 冷启动上
# （首次 /tsx/ 会先 ensure deps 再编译），而 npm install 在慢网下要几分钟，
# 让第一个请求干等到超时。deploy 机器上预装了 esbuild 时这里应当秒过。
if command -v esbuild >/dev/null 2>&1 || command -v tsc >/dev/null 2>&1; then
  echo "tsx: 已有全局转译器（$(command -v esbuild || command -v tsc)），跳过 npm install" >&2
elif command -v npm >/dev/null 2>&1; then
  # --no-audit --no-fund：省掉两次多余的联网往返；失败不阻断（引擎会给出明确错误）。
  if ! npm install --prefix "$DEPS" --no-audit --no-fund --silent esbuild >"$DEPS/npm-install.log" 2>&1; then
    echo "tsx: npm install esbuild 失败（详见 $DEPS/npm-install.log）—— 需要联网或预置包" >&2
  fi
else
  echo "tsx: 未安装 node/npm —— 请 pkg_add -I node 后重试（引擎会明确报错，不会假装成功）" >&2
fi

echo "tsx: deps ready ($DEPS)" > "$DEPS/manifest.txt"
