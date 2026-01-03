#!/bin/sh
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/hold_open" "$ROOT/hold_open.c"
