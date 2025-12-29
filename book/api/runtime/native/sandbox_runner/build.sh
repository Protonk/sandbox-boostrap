#!/bin/sh
# Build sandbox_runner, sandbox_reader, and sandbox_writer in-place.
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/sandbox_runner" "$ROOT/sandbox_runner.c" -lsandbox
cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/sandbox_reader" "$ROOT/sandbox_reader.c" "$ROOT/sandbox_io.c" -lsandbox
cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/sandbox_writer" "$ROOT/sandbox_writer.c" "$ROOT/sandbox_io.c" -lsandbox
