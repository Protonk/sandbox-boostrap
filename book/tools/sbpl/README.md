# SBPL tools

This directory holds host-bound helpers for working with SBPL inputs on the fixed
SANDBOX_LORE baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`). These
tools are distinct from shared APIs in `book/api/` and profile sources in
`book/profiles/`.

Current contents:

- `corpus/` – curated SBPL specimen set with historical provenance.
- `corpus/catalog.py` – quick summary of the corpus directory.
- `compile_profile/` – minimal C reference compiler (`sandbox_compile_file` → `.sb.bin`) for debugging/cross-checks.
- `oracles/` – dataset runners for structural SBPL↔blob oracles (e.g. network matrix runner).
- `wrapper/` – SBPL apply harness for runtime probes (see `wrapper/README.md`).
- `trace_shrink/` – SBPL trace + shrink tool built from the shrink-trace experiment.

This corpus is about **inputs**, not policy semantics. Any claim about behavior
must cite the relevant mapping or validation artifacts.

`book/tools/sbpl/corpus/PROVENANCE.json` records historical origin pointers for
corpus entries; it is not a contract and is not used by tests.

Quick usage (from repo root):

```sh
python3 book/tools/sbpl/corpus/catalog.py
```
