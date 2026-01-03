#!/bin/sh
# Build sandbox_runner, sandbox_reader/sandbox_writer, and openat variants in-place.
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/sandbox_runner" "$ROOT/sandbox_runner.c" -lsandbox
cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/sandbox_reader" "$ROOT/sandbox_reader.c" "$ROOT/sandbox_io.c" -lsandbox
cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/sandbox_writer" "$ROOT/sandbox_writer.c" "$ROOT/sandbox_io.c" -lsandbox
cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/sandbox_openat_reader" "$ROOT/sandbox_openat_reader.c" "$ROOT/sandbox_io.c" -lsandbox
cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/sandbox_openat_writer" "$ROOT/sandbox_openat_writer.c" "$ROOT/sandbox_io.c" -lsandbox
cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/sandbox_openat_rootrel_reader" "$ROOT/sandbox_openat_rootrel_reader.c" "$ROOT/sandbox_io.c" -lsandbox
cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/sandbox_openat_rootrel_writer" "$ROOT/sandbox_openat_rootrel_writer.c" "$ROOT/sandbox_io.c" -lsandbox
