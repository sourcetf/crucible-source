#!/bin/sh
mkdir -p "${DEPS_DIR:-./deps}/bin"
echo "c deps ok" > "${DEPS_DIR:-./deps}/.ready"
