#!/bin/sh
# Generate ECH material via OpenBSD boringssl package `bssl generate-ech`.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/state/ech"
PUBLIC_NAME="${1:-crucible.local}"

export PATH="/usr/local/bin:/usr/local/sbin:${PATH:-}"

BSSL=""
for candidate in \
  "${ROOT}/target/tls-libs/boringssl/bin/bssl" \
  /usr/local/eboringssl/bin/bssl \
  bssl; do
  if [ -x "$candidate" ] 2>/dev/null || command -v "$candidate" >/dev/null 2>&1; then
    BSSL="$candidate"
    break
  fi
done

if [ -z "${BSSL}" ]; then
  echo "generate_ech: install boringssl package (pkg_add boringssl)" >&2
  exit 1
fi

mkdir -p "${OUT}"
"${BSSL}" generate-ech \
  -out-ech-config-list "${OUT}/ech_config_list.bin" \
  -out-ech-config "${OUT}/ech_config.bin" \
  -out-private-key "${OUT}/ech_key.bin" \
  -public-name "${PUBLIC_NAME}" \
  -config-id 1

# Crucible admin/config PEM paste format
python3 - <<'PY' "${OUT}/ech_config.bin" "${OUT}/ech_key.bin" "${OUT}/ech_keys.pem"
import base64, pathlib, sys
cfg, key, out = sys.argv[1:4]
def b64(path):
    data = pathlib.Path(path).read_bytes()
    enc = base64.encodebytes(data).decode("ascii")
    return enc
pem = (
    "-----BEGIN ECH CONFIG-----\n"
    + b64(cfg)
    + "-----END ECH CONFIG-----\n"
    "-----BEGIN ECH PRIVATE KEY-----\n"
    + b64(key)
    + "-----END ECH PRIVATE KEY-----\n"
)
pathlib.Path(out).write_text(pem)
print(f"wrote {out}")
PY

echo "generate_ech: ${OUT}/ech_keys.pem (set ssl.ech=true ssl.ech_keys=state/ech/ech_keys.pem)"
