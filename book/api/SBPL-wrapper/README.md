# SBPL Wrapper

Role: apply SBPL text or compiled sandbox blobs to a process for runtime probes (e.g., `sbpl-graph-runtime`).

Use when: you need a controlled harness around `sandbox_init` / `sandbox_apply` instead of ad hoc `sandbox-exec`.

Host baseline: see `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`; requires `libsandbox.dylib`.

Status: SBPL mode works; compiled-blob mode relies on `sandbox_apply` and routinely hits apply gates (`EPERM`) for platform blobs. Treat apply failures as `blocked`, not as evidence that a profile is absent.

Build:

```sh
cd book/api/SBPL-wrapper
clang -Wall -Wextra -o wrapper wrapper.c -lsandbox
```

Run:

```sh
# SBPL text
./wrapper --sbpl path/to/profile.sb -- <cmd> [args...]

# Compiled blob
./wrapper --blob path/to/profile.sb.bin -- <cmd> [args...]
```

The wrapper applies the selected profile to itself, then `execvp`s the command. On failure it prints the sandbox error and exits non-zero before exec.
