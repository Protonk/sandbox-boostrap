# SBPL Wrapper

Role: apply SBPL text or compiled sandbox blobs to a process for runtime probes (e.g., `sbpl-graph-runtime`).

Use when: you need a controlled harness around `sandbox_init` / `sandbox_apply` instead of ad hoc `sandbox-exec`.

World: see `world_id sonoma-14.4.1-23E224-arm64-dyld-a3a840f9`; requires `libsandbox.dylib`.

Status: SBPL mode works; compiled-blob mode relies on `sandbox_apply` and routinely hits apply gates (`EPERM`) for platform blobs. Treat apply failures as `blocked`, not as evidence that a profile is absent.

Operational preflight (apply-gate avoidance):

```sh
python3 book/tools/preflight/preflight.py scan path/to/profile.sb
python3 book/tools/preflight/preflight.py scan path/to/profile.sb.bin
```

If preflight reports `likely_apply_gated_for_harness_identity`, treat it as an environment constraint on this host (blocked evidence), not as a policy decision; see `troubles/EPERMx2.md`.

Build:

```sh
cd book/tools/sbpl/wrapper
clang -Wall -Wextra -o wrapper wrapper.c -lsandbox -framework Security -framework CoreFoundation
```

Run:

```sh
# SBPL text
./wrapper --sbpl path/to/profile.sb -- <cmd> [args...]

# Compiled blob
./wrapper --blob path/to/profile.sb.bin -- <cmd> [args...]

# Preflight policy (default: enforce)
./wrapper --preflight enforce --sbpl path/to/profile.sb -- <cmd> [args...]
./wrapper --preflight off --blob path/to/profile.sb.bin -- <cmd> [args...]
./wrapper --preflight force --sbpl path/to/profile.sb -- <cmd> [args...]

# Compile-only (no apply): SBPL -> .sb.bin
./wrapper --compile path/to/profile.sb --out path/to/profile.sb.bin
```

The wrapper applies the selected profile to itself, then `execvp`s the command. On failure it prints the sandbox error and exits non-zero before exec.

It emits one JSONL marker per phase on stderr so runners can classify failures mechanically without relying on substring matching:

- `tool:"sbpl-apply"` with `stage:{apply,applied,exec}` for the apply/exec phases
- `tool:"sbpl-compile"` with `stage:"compile"` for compile-only runs (`--compile`)
- `tool:"sbpl-preflight"` with `stage:"preflight"` for wrapper-side static preflight (apply-gate avoidance)
