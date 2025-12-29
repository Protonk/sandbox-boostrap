# profile.compile

Host-scoped SBPL compilation helpers for the Sonoma baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).

This surface is intentionally **structural**:
- Inputs are SBPL (`.sb`) source text/files.
- Outputs are compiled profile blob bytes plus minimal metadata; it does **not** claim sandbox semantics.
- It does **not** apply/run profiles (`sandbox_init` / `sandbox_apply`); runtime execution lives under `book/api/runtime/`.

## Current surface

### Library API (stable)

- `from book.api.profile.compile import compile_sbpl_file, compile_sbpl_string`
- `from book.api.profile.compile import CompileResult, hex_preview`
- Compile-time parameterization:
  - `from book.api.profile.compile import ParamsInput, ParamPairs`
  - Pass `params={...}` (mapping) or `params=[("KEY","VALUE"), ...]` (pairs) to `compile_sbpl_*`.

`CompileResult` is a small dataclass carrying:
- `blob: bytes` (the compiled `.sb.bin` bytes),
- `profile_type: int`,
- `length: int` (byte count).

### CLI

`python -m book.api.profile compile <paths...> [--out PATH | --out-dir DIR] [--param KEY=VALUE] [--params-json PATH]`

## Compile-time params (SBPL `(param "...")`)

On this baseline, compile-time parameterization is implemented via libsandbox’s “params handle” APIs:
- `sandbox_create_params()`
- `sandbox_set_param(handle, key, value)`
- `sandbox_free_params(handle)`

The resulting handle is passed as the second argument to `sandbox_compile_string` / `sandbox_compile_file`.

This is intentionally separated from apply/runtime parameterization (for example argv-style `KEY VALUE ... NULL` vectors used by higher-level init/apply entry points); `profile.compile` is only about producing compiled bytes.

## Code layout

- `book/api/profile/compile/api.py`: high-level wrappers (`compile_sbpl_file`, `compile_sbpl_string`).
- `book/api/profile/compile/libsandbox.py`: ctypes bindings for `sandbox_compile_*` and the compile-time params-handle interface.
