#!/bin/sh
# Optional deps bootstrap for rust sample
mkdir -p "${DEPS_DIR:-./deps}/bin"
echo "rust app deps ok" > "${DEPS_DIR:-./deps}/.ready"
