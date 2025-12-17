## Purpose

Map how this host’s `libsandbox` populates the per-node u16 payload slot (historically “field2”) in compiled profiles, and align those observations with the Filter Vocabulary Map **only when warranted by structural role**. This experiment is about **userland emission and compiled-blob structure**; it does not attempt to interpret kernel semantics.

## Baseline & scope

- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs:
  - `book/api/sbpl_compile` (compile SBPL to a blob).
  - `book/api/decoder` + `book/graph/concepts/validation/profile_ingestion.py` (decode/slice compiled blobs).
  - Trimmed `libsandbox` slice under `book/graph/mappings/dyld-libs/` (static-only inspection for Phase B).
- Structural backbone (world-scoped):
  - Tag layouts: `book/graph/mappings/tag_layouts/tag_layouts.json` (`status: ok`, record_size_bytes=8).
  - Tag u16 roles: `book/graph/mappings/tag_layouts/tag_u16_roles.json` (`status: ok`, `filter_vocab_id` vs `arg_u16`).
- Out of scope:
  - Any runtime `sandbox_apply` work.
  - Kernel-side interpretation of the blob (tracked elsewhere; see `book/experiments/field2-filters/Report.md`).

## Status (current)

- **Phase A (SBPL→blob matrix): partial.**
  - Matrices refreshed under the world-scoped stride=8 framing:
    - `out/matrix_v1_field2_encoder_matrix.json` (baseline, regex-free).
    - `out/matrix_v2_field2_encoder_matrix.json` (arg-variance probe; still structurally useful, but not relied on for strong conclusions).
  - A small **network argument matrix** now provides byte-level witnesses for domain/type/proto argument deltas without relying on runtime:
    - Specimens: `sb/network_matrix/*.sb` (manifest: `sb/network_matrix/MANIFEST.json`).
    - Outputs: `out/network_matrix/index.json`, `out/network_matrix/node_records.jsonl`, `out/network_matrix/blob_diffs.json`.
    - This is the current “most falsifiable” Phase A sub-surface for network arg emission.
  - Interpretation is intentionally conservative: these tables are *descriptive* (what tags/u16 payloads appear), not a proof of per-tag semantics.
- **Phase B (static RE of `libsandbox`): partial.**
  - Initial encoder-site mapping exists at `out/encoder_sites.json` (not promoted; evidence remains incomplete).

## Phase A — what the matrices are (and are not)

Phase A answers a narrow question: **“When we compile a small SBPL probe set, what tags and u16 payload values show up in the resulting node stream?”**

The matrices:

- Parse the node stream as an 8-byte record stream (`tag`,`kind`,u16[0..2]) using `profile_ingestion` section slicing.
- Record a u16 payload as `field2_raw` (plus a diagnostic hi/lo split `field2_hi`/`field2_lo`).
- Attempt heuristic literal association (`literal_refs`) by scanning node bytes for literal offsets/indices; this is best-effort and not a promoted anchor mapping.
- Provide an optional `filters.json` resolution (`filter_name`) as a *hint only*:
  - Do **not** treat in-range values as proof of a Filter Vocabulary ID unless corroborated by structural role (`tag_u16_roles.json`) and/or independent witnesses.

Phase A also carries experiment-local tag-layout overrides at `out/tag_layout_overrides.json`. These are **not** a substitute for world-scoped tag layouts; they are staging knobs for this experiment’s parsing and should be treated as `partial`/`hypothesis` unless and until promoted by the shared validation→mappings pipeline.

## Phase A — artifacts

- SBPL probes:
  - `sb/matrix_v1.sb`
  - `sb/matrix_v2.sb`
  - Network arg matrix specimens under `sb/network_matrix/` (see `sb/network_matrix/MANIFEST.json`)
- Compiled blobs and summaries:
  - `out/matrix_v1.sb.bin`, `out/matrix_v1.sb.inspect.json`, `out/matrix_v1.inspect.json`, `out/matrix_v1.op_table.json`
  - `out/matrix_v2.sb.bin`, `out/matrix_v2.inspect.json`
- Matrices:
  - `out/matrix_v1_field2_encoder_matrix.json`
  - `out/matrix_v2_field2_encoder_matrix.json`
- Network arg matrix outputs:
  - `out/network_matrix/index.json` (per-spec section boundaries + tag counts)
  - `out/network_matrix/node_records.jsonl` (joinable node record samples keyed by `spec_id`)
  - `out/network_matrix/blob_diffs.json` (byte diffs + record annotations)
- Legacy (kept for historical continuity; prefer the `matrix_v*` outputs):
  - `out/field2_encoder_matrix.json`

## Phase A — network arg matrix (byte-level witness)

This sub-track exists to answer a narrow question with minimal ambiguity:

> “When we change only one socket argument in SBPL, where (and how) does the compiled blob change?”

Evidence is static and local: SBPL sources + compiled blobs + byte diffs. No kernel-semantic claims.

Current strongest witnesses live in `out/network_matrix/blob_diffs.json`:

- Single-arg deltas are isolated to a **single byte change in the nodes region** (no literal-pool diffs) for the minimal specimens:
  - `domain_af_inet` ↔ `domain_af_system`: `a_byte=2` ↔ `b_byte=32` (AF_SYSTEM compiles to `32` on this host baseline).
  - `type_sock_stream` ↔ `type_sock_dgram`: `1` ↔ `2`.
  - `proto_tcp` ↔ `proto_udp`: `6` ↔ `17`.
- Under `triple_all_tcp` ↔ `triple_all_udp` (domain fixed at AF_INET), the type+proto changes show up as two byte deltas in the same nodes region (see the pair entry in `out/network_matrix/blob_diffs.json`).

This is sufficient to treat “network arg bytes are serialized into the compiled blob (nodes section)” as an experiment-local, world-scoped fact, and it provides a concrete join point for Phase B’s `_emit_network` disassembly.

## Phase B — artifacts and partial findings

- `out/encoder_sites.json` records a small set of encoder-side sites with addresses and evidence notes (partial):
  - `_emit` uses `_sb_mutable_buffer_write` to append bytes to the mutable buffer.
  - `_emit_network` emits three items (domain/type/proto) via `_emit` with widths {1,1,2} after padding to an 8-byte boundary when needed.
  - `_record_condition_data` threads emitted data into a per-op list/table (shape still under exploration).
  - The builder’s mutable buffer handle is consistently addressed at `builder+0xe98` across encoder helpers; `_compile` calls `_sb_mutable_buffer_make_immutable` on that handle.
- Static RE excerpts (world-scoped, but interpretation remains partial):
  - `out/static_re/emit_network.otool.txt`
  - `out/static_re/emit.otool.txt`
  - `out/static_re/record_condition_data.otool.txt`

These are **static** witnesses from the dyld slice for this world; they do not establish how the kernel interprets the resulting tables/structures.

## Blockers / risks

- Phase A cannot, by itself, disambiguate “u16 payload is a vocab ID” vs “u16 payload is an argument u16” for tags whose role is still under exploration. Treat any `filter_name` resolution in the matrices as a hint only.
- Phase B work is inherently brittle: without a clean, byte-level join between encoder-side writes and the exact blob sections the decoder reads, it should not be promoted into mappings.

## Running / refreshing

- Refresh Phase A matrices (recompiles `sb/matrix_v1.sb` and `sb/matrix_v2.sb` and rewrites `out/matrix_v*_field2_encoder_matrix.json`):
  - `python3 book/experiments/libsandbox-encoder/run_phase_a.py`
- Refresh Phase A network arg matrix (recompiles `sb/network_matrix/*.sb` and rewrites `out/network_matrix/*`):
  - `python3 book/experiments/libsandbox-encoder/run_network_matrix.py`
  - `python3 book/experiments/libsandbox-encoder/diff_network_matrix.py`

## Next steps

- If the SBPL compiler accepts a `socket-protocol` value with a non-zero high byte (e.g., >255), add it to the network matrix so we can witness `_emit_network`’s `len=2` behavior directly in the blob diff (otherwise record the rejection as a negative result).
- In Phase B, connect `_emit_network`’s (domain/type/proto) writes to a concrete location in the compiled blob (condition-data tables vs node stream), so the compiler-side interpretation can be expressed as a byte-level witness rather than a narrative guess.
