## Purpose

Map how this host’s `libsandbox` encodes filter arguments into the `field2` u16 in compiled profiles and align those encodings with the Filter Vocabulary Map (`book/graph/mappings/vocab/filters.json`, status: ok). The kernel is treated as consuming a raw u16; the focus here is purely on userland emission.

## Baseline & scope

- Host: macOS 14.4.1 (23E224), Apple Silicon, SIP enabled (`book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`).
- Inputs: `book/api/sbpl_compile`, `book/api/decoder`, trimmed `libsandbox` slice under `book/graph/mappings/dyld-libs/`.
- Out of scope: runtime `sandbox_apply` or kernel-side interpretation (covered by `field2-filters`).

## Plan & execution log

- Phase A — SBPL→blob matrix (encoder output view): not started.
- Phase B — libsandbox internals (encoder implementation view): not started.

## Evidence & artifacts

- Pending: `out/field2_encoder_matrix.json`, `out/encoder_sites.json`, SBPL probes under `sb/`.

## Blockers / risks

- Phase B is expected to be partial/brittle unless encoder patterns are obvious; no promotion to `book/graph/mappings/*` without corroboration.

## Next steps

- Stand up Phase A probes and capture the matrix.
- Begin Phase B disassembly once Phase A is stable.
