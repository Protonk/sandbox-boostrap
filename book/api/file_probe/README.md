# File Probe

Role: minimal C helper that performs a single `open` + `read` or `open` + `write` and reports the result as JSON. Used by runtime probes (e.g., `sbpl-graph-runtime`) as the target process once a profile is applied by `SBPL-wrapper/wrapper`.

Use when: you need a deterministic, low-noise file access to test allow/deny outcomes under a sandbox profile.

Host baseline: see `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)`.

Build:

```sh
cd book/api/file_probe
clang -Wall -Wextra -o file_probe file_probe.c
```

Run examples:

```sh
./file_probe read /tmp/probe.txt
./file_probe write /tmp/probe.txt
```

Output: one JSON line like `{"op":"read","path":"/tmp/probe.txt","rc":0,"errno":0}`. Exit code is `0` on success, `1` with `errno` captured in the JSON payload for failures.
