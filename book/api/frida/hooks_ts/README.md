# TypeScript hooks

`book/api/frida/hooks_ts/` is the TypeScript authoring tree for Frida hooks.

- Runtime-consumed hook artifacts live in `book/api/frida/hooks/` as `*.js` + `*.manifest.json`.
- This tree is compiled and staged into the runtime catalog by `python -m book.api.frida.cli build-ts-hooks`.

This directory is intentionally local-scoped (it does not introduce a repo-wide Node toolchain).

