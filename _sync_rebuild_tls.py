#!/usr/bin/env python3
"""Sync TLS-critical files and rebuild full stack on OpenBSD."""
from __future__ import annotations

import time
from pathlib import Path

from _remote import put_bytes, run

ROOT = Path(__file__).resolve().parent

FILES = [
    "build.rs",
    "Cargo.toml",
    "config.toml",
    "src/main.rs",
    "libs/tls-common/peek_io.c",
    "libs/tls-common/peek_io.h",
    "libs/tls-common/pem_util.c",
    "libs/tls-common/pem_util.h",
    "libs/tls-nss/nss_shim.c",
    "libs/tls-tomcrypt/tc_shim.c",
    "scripts/build_libtomcrypt.sh",
    "src/server/tls/accept.rs",
    "src/server/tls/boring_path.rs",
    "src/server/tls/ech_pem.rs",
    "src/server/tls/legacy_io.rs",
    "src/server/tls/mod.rs",
    "src/server/tls/tls_nss.rs",
    "src/server/tls/tls_tomcrypt.rs",
]


def main() -> None:
    for rel in FILES:
        local = ROOT / rel
        data = local.read_bytes()
        put_bytes(f"/crucible/{rel.replace(chr(92), '/')}", data)
        print("uploaded", rel, len(data))

    # Make scripts executable
    run("chmod +x /crucible/scripts/build_libtomcrypt.sh /crucible/configure")

    cmd = (
        "cd /crucible && "
        "./configure --target=openbsd --enable-nss --enable-tomcrypt && "
        "make release 2>&1"
    )
    print("building...")
    out, err, code = run(cmd, timeout=1800)
    Path("build_tls_log.txt").write_text(out + "\n" + err, encoding="utf-8", errors="replace")
    # Print tail
    lines = (out + err).splitlines()
    print("\n".join(lines[-80:]))
    raise SystemExit(code)


if __name__ == "__main__":
    main()
