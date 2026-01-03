#!/bin/sh
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

PY_CONFIG="${PYTHON_CONFIG:-python3.14-config}"
if ! command -v "$PY_CONFIG" >/dev/null 2>&1; then
  PY_CONFIG="python3-config"
fi
if ! command -v "$PY_CONFIG" >/dev/null 2>&1; then
  echo "frida_attach_helper: python-config not found" >&2
  exit 1
fi

CFLAGS="$($PY_CONFIG --embed --cflags)"
LDFLAGS="$($PY_CONFIG --embed --ldflags)"

cc -Wall -Wextra -O2 -o "$ROOT/frida_attach_helper" "$ROOT/frida_attach_helper.c" $CFLAGS $LDFLAGS
