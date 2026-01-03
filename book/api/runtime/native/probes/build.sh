#!/bin/sh
# Build runtime probe binaries in-place.
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/mach_probe" "$ROOT/mach_probe.c"
cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/sandbox_check_probe" "$ROOT/sandbox_check_probe.c"
cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/sandbox_check_self_apply_probe" "$ROOT/sandbox_check_self_apply_probe.c" "$ROOT/sandbox_profile.c" -lsandbox
cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/sandbox_mach_probe" "$ROOT/sandbox_mach_probe.c" "$ROOT/sandbox_profile.c" -lsandbox
cc -Wall -Wextra -O2 -std=c11 -fblocks -o "$ROOT/xpc_probe" "$ROOT/xpc_probe.c"
cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/iokit_probe" "$ROOT/iokit_probe.c" -framework IOKit -framework CoreFoundation -framework IOSurface
cc -Wall -Wextra -O2 -std=c11 -o "$ROOT/sandbox_iokit_probe" "$ROOT/sandbox_iokit_probe.c" "$ROOT/sandbox_profile.c" -framework IOKit -framework CoreFoundation -framework IOSurface -lsandbox
