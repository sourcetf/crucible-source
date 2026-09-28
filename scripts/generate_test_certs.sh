#!/bin/sh
# 生成 config.toml 监听器所需的 RSA + EC 测试证书。
#
# 依赖取向（用户要求：openssl **不作为项目依赖** —— 现场可能已卸载它）：
#   * 仓库**自带** cert.pem / key.pem / cert_ec.pem / key_ec.pem，因此正常部署路径
#     **根本不需要任何生成工具**；
#   * 旧实现的问题正是没意识到这一点：它在第 5 行就 `openssl version` 失败即 `exit 1`
#     （还配着 `set -e`）—— 即使证书**全都已经存在、什么都没必要做**，脚本仍然报错退出。
#     这会让 `acceptance.sh` 这类调用方在「卸载了 openssl 的正常机器」上直接失败。
#   * 只有证书**真的缺失**时才需要生成器：优先 `bssl`（BoringSSL 自带工具，与项目技术栈一致），
#     找不到再退回 `openssl`，都没有就给出明确指引（而不是一句 "openssl required"）。
set -e
cd "$(dirname "$0")/.."

have_all_certs() {
  [ -f cert.pem ] && [ -f key.pem ] && [ -f cert_ec.pem ] && [ -f key_ec.pem ]
}

mkdir -p state/ech
if [ ! -f state/ech/ech_keys.pem ] && [ -x scripts/generate_ech.sh ]; then
  sh scripts/generate_ech.sh crucible.local >/dev/null 2>&1 || true
fi

if have_all_certs; then
  echo "test certs ready（仓库自带，无需生成）: cert.pem key.pem cert_ec.pem key_ec.pem"
  exit 0
fi

# 从这里开始才需要生成器
gen_rsa() {
  if command -v bssl >/dev/null 2>&1 && bssl generate-rsa-key --help >/dev/null 2>&1; then
    bssl generate-rsa-key -out key.pem && bssl selfsign -key key.pem -out cert.pem -subject /CN=crucible.local
  elif command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -nodes -subj /CN=crucible.local
  else
    return 1
  fi
}
gen_ec() {
  if command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
      -keyout key_ec.pem -out cert_ec.pem -days 3650 -nodes -subj /CN=crucible.local
  else
    return 1
  fi
}

if [ ! -f cert.pem ] || [ ! -f key.pem ]; then
  gen_rsa || {
    echo "缺少 cert.pem/key.pem 且本机没有可用的证书生成器（bssl / openssl）。" >&2
    echo "两种处理方式：① 从仓库取出自带的 cert.pem/key.pem（推荐，部署本不需要生成）；" >&2
    echo "             ② 安装 boringssl（pkg_add boringssl）以获得 bssl。" >&2
    exit 1
  }
fi
if [ ! -f cert_ec.pem ] || [ ! -f key_ec.pem ]; then
  gen_ec || {
    echo "缺少 cert_ec.pem/key_ec.pem 且本机没有可用的证书生成器（bssl / openssl）。" >&2
    echo "同 ①：从仓库取出自带的 EC 证书即可。" >&2
    exit 1
  }
fi
echo "test certs ready: cert.pem key.pem cert_ec.pem key_ec.pem"