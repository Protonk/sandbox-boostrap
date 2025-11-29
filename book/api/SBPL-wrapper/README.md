# SBPL Wrapper

This hosts a small helper that can take SBPL text or a compiled sandbox blob and apply it to a process for runtime probes. The intent is to support system profiles (`airlock`, `bsd`) and other cases where we want to exercise compiled policies under the runtime-checks harness.

Current status: SBPL mode is implemented; compiled-blob mode is still TODO.

## Usage (SBPL mode)

Build:

```sh
cd book/api/SBPL-wrapper
clang -Wall -Wextra -o wrapper wrapper.c -lsandbox
```

Run:

```sh
./wrapper --sbpl path/to/profile.sb -- <cmd> [args...]
```

The wrapper applies the SBPL profile via `sandbox_init` to the current process, then execs the command. If apply fails, it prints the error and exits non-zero before exec.
