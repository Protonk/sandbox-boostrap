# Hook Generator Input v1

This document defines the stable v1 JSON input format for the Frida hook generator (`python -m book.api.frida.cli generate-hook`).

## Input shape (JSON object)

Required keys:

- `hook_name` (string): Filename stem for the generated hook. Must be a safe stem (no path separators; `[A-Za-z0-9_-]+`).
- `description` (string): Human summary for the manifest `hook.summary`.
- `targets` (array): Each element is an object with:
  - `module` (string): Module name, e.g. `libsystem_sandbox.dylib`
  - `exports` (optional array of strings): Exact export names to attach to.
  - `export_patterns` (optional array of strings): Regex strings captured as metadata only (no discovery pipeline implied).

At least one of `exports` or `export_patterns` must be present per target.

Optional keys:

- `defaults` (object):
  - `emit_backtrace` (bool, default `false`)
  - `emit_args` (bool, default `true`)
  - `emit_return` (bool, default `false`)

## Determinism rules

- No timestamps or environment-derived values are permitted in generated outputs.
- Targets are normalized by sorting by `module` lexicographically.
- `exports` and `export_patterns` are normalized by sorting lexicographically (duplicates removed).

## Example

See `book/api/frida/fixtures/generator_inputs/example_exports_v1.json`.

