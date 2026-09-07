#!/bin/sh
mkdir -p "${DEPS_DIR:-./deps}"
echo "php deps ok" > "${DEPS_DIR:-./deps}/.ready"
