## Purpose

Map how this host’s `libsandbox` populates the per-node u16 payload slot (historically “field2”) in compiled profiles, and align those observations with the Filter Vocabulary Map **only when warranted by structural role**. This experiment is about **userland emission and compiled-blob structure**; it does not attempt to interpret kernel semantics.

## Baseline & scope

- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs:
  - `book/api/profile` (compile SBPL to a blob).
  - `book/api/profile/decoder/` + `book/graph/concepts/validation/profile_ingestion.py` (decode/slice compiled blobs).
  - Trimmed `libsandbox` slice under `book/evidence/graph/mappings/dyld-libs/` (static-only inspection for Phase B).
- Structural backbone (world-scoped):
  - Tag layouts: `book/evidence/graph/mappings/tag_layouts/tag_layouts.json` (`status: ok`, record_size_bytes=8).
  - Tag u16 roles: `book/evidence/graph/mappings/tag_layouts/tag_u16_roles.json` (`status: ok`, `filter_vocab_id` vs `arg_u16`).
- Out of scope:
  - Any runtime `sandbox_apply` work.
  - Kernel-side interpretation of the blob (tracked elsewhere; see `book/evidence/experiments/field2-final-final/field2-filters/Report.md`).

## Status (current)

- **Phase A (SBPL→blob matrix): partial.**
  - Matrices refreshed under the world-scoped stride=8 framing:
    - `out/matrix_v1_field2_encoder_matrix.json` (baseline, regex-free).
    - `out/matrix_v2_field2_encoder_matrix.json` (arg-variance probe; still structurally useful, but not relied on for strong conclusions).
  - A small **network argument matrix** now provides byte-level witnesses for domain/type/proto argument deltas without relying on runtime:
    - Specimens: `sb/network_matrix/*.sb` (manifest: `sb/network_matrix/MANIFEST.json`).
    - Outputs: `out/network_matrix/index.json`, `out/network_matrix/node_records.jsonl`, `out/network_matrix/blob_diffs.json`, `out/network_matrix/join_records.jsonl`, `out/network_matrix/join_summary.json`.
    - This is the current “most falsifiable” Phase A sub-surface for network arg emission and for joining `_emit_network`’s {1,1,2} writes to concrete blob structure.
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
  - `out/network_matrix/join_records.jsonl` (diff offsets normalized into 8-byte record context for both sides of each pair)
  - `out/network_matrix/join_summary.json` (rollups keyed by `pair_id`)
  - `out/network_matrix/oracle_tuples.json` (experiment-local extractor output for `(domain,type,proto)`)
- Oracle extractor:
  - `oracle_network_matrix.py` (HISTORICAL; original experiment-local oracle)
  - Maintained oracle: `book/api/profile/oracles/` (guarded by parity tests against this corpus)
- Legacy (kept for historical continuity; prefer the `matrix_v*` outputs):
  - `out/field2_encoder_matrix.json`

## Phase A — network arg matrix (byte-level witness)

This sub-track exists to answer a narrow question with minimal ambiguity:

> “When we change only one socket argument in SBPL, where (and how) does the compiled blob change?”

Evidence is static and local: SBPL sources + compiled blobs + byte diffs. No kernel-semantic claims.

Current strongest witnesses live in `out/network_matrix/blob_diffs.json`:

- Single-arg deltas land in a stable u16 slot in the nodes region for the minimal specimens:
  - `domain_af_inet` ↔ `domain_af_system`: `a_byte=2` ↔ `b_byte=32` (AF_SYSTEM compiles to `32` on this host baseline).
  - `type_sock_stream` ↔ `type_sock_dgram`: `1` ↔ `2`.
  - `proto_tcp` ↔ `proto_udp`: `6` ↔ `17`.
  - `proto_tcp` ↔ `proto_256`: two-byte span witness for the proto u16 (TCP `0x0006` ↔ numeric `0x0100`).
- Pairwise combined forms (domain+type / domain+proto / type+proto; both `require-all` and `require-any`) show argument deltas in a different structural role: the varying arg lands in `u16_index=0` for a `tag=0` record whose kind byte matches the argument family (`0x0b`/`0x0c`/`0x0d` for domain/type/proto); see the `pair_*` diff pairs in `out/network_matrix/blob_diffs.json` and the rollups in `out/network_matrix/join_summary.json`.
- Pairwise combined proto high-byte witness: the `pair_*_tcp_vs_*_256` pairs flip both bytes of the same `u16_index=0` slot (`within_record_offset=2/3`), matching a 16-bit proto value.
- For the witnessed triple forms, domain/type/proto values live in the record header bytes: interpret `(tag,kind)` as a little-endian u16 value. Small values change only the tag byte (`within_record_offset=0`) because kind stays `0`; the proto 256 witness also flips the kind byte (`within_record_offset=1`) to carry the high byte; see `triple_*_tcp_vs_*_256` and `out/network_matrix/join_summary.json`.
- Order-variant require-all pairs (`pair_dt_all_inet_stream_order2`, `pair_dp_all_inet_tcp_order2`, `pair_tp_all_stream_tcp_order2`) are included as cross-checks; their diffs span multiple bytes and are excluded from the small-diff join scoring (see `out/network_matrix/join_hypotheses.json`).

This is sufficient to treat “network arg bytes are serialized into the compiled blob (nodes section)” as an experiment-local, world-scoped fact, and it provides a concrete join point for Phase B’s `_emit_network` disassembly.

## Branch: byte-level structural join for `_emit_network` (Phase A → Phase B)

This branch exists to close a specific gap: we have (a) static RE evidence that `_emit_network` emits domain/type/proto as widths `{1,1,2}`, and (b) a Phase A witness that controlled SBPL deltas produce localized byte diffs in the compiled blob. What we **do not yet have** is a stable, byte-level mapping from `_emit_network`’s “writes into a mutable buffer” to *where those bytes live in the compiled blob structure* (node stream vs any other per-op condition-data region) and which record/tag/field boundaries explain the observed diffs.

### Why this matters (profile oracle)

For this branch, the compiled profile blob is the oracle: SBPL→compile→blob bytes are the primary witness, and every structural claim should be phrased so it can be mechanically checked against those bytes. Static RE and decoder output are supporting tools, but without a byte-level join they remain narrative and brittle. Closing this join is the minimal prerequisite for promoting any “encoder-side structure” claim into shared decoding/mapping tooling.

### What we expect to learn

- Which compiled-blob region contains the domain/type/proto argument bytes for:
  - single-arg forms (`socket-domain` only, `socket-type` only, `socket-protocol` only), and
  - combined forms (domain+type+proto under `require-all` / `require-any` / nested forms).
- Whether those bytes appear as a contiguous sequence (as suggested by `_emit_network`) or are threaded through multiple records/structures.
- Which record boundaries (8-byte framing) and which u16 slots are the structural “roles” for these bytes (arg u16 vs vocab-like u16), so Phase B can be expressed as a concrete mapping instead of a guess.

The matrix now has explicit high-byte witnesses for proto in:
- minimal single-arg form (`proto_tcp_vs_256`),
- pairwise combined forms (`pair_*_tcp_vs_*_256`), and
- triple combined forms (`triple_*_tcp_vs_*_256`).

### How we did it (static-first, current)

- Re-ran the Phase A network matrix pipeline to keep `out/network_matrix/*` current and to protect against accidental drift in probes/layout assumptions.
- Extended the SBPL specimen matrix with order-variant require-all pairs for domain+type, domain+proto, and type+proto.
- Added an experiment-local join analyzer (`analyze_network_join.py`) that scores small-diff pairs and emits `out/network_matrix/join_hypotheses.json`.
- Used the analyzer output to score join hypotheses; the small-diff pairs are consistent across the single, pairwise, and triple patterns on this world (status `ok` in `join_hypotheses.json`).
- Updated `out/encoder_sites.json` so `_emit_network` points at the join hypothesis summary alongside the diff/join artifacts.
- Added an experiment-local guardrail (`check_network_join.py`) that fails if the join hypotheses report violations.
- Kept the experiment-local blob oracle (`oracle_network_matrix.py`) in sync with the matrix (updated `out/network_matrix/oracle_tuples.json`).

### Trace-backed join (encoder-write-trace)

We can now tie encoder write events to blob offsets directly, without relying on static RE alone. Using the hardware‑breakpoint tracer, we ran a minimal network‑matrix subset plus a baseline and produced:

- `out/network_matrix/encoder_write_join.json` — per‑spec join windows (base offset, window length, witnessed vs hole ranges).
- `out/network_matrix/encoder_write_events.jsonl` — write_event → blob_offset spans (no payload bytes).

Findings (compile‑only, still partial):

- All traced network‑matrix specs align to gapped windows (lengths 484/492/500) with a consistent `[394,400)` hole; the baseline `allow_all` aligns to a 416‑byte window with the same hole.
- `book/evidence/experiments/profile-pipeline/encoder-write-trace/out/trace_join_check.json` reports `pairs_checked: 35` with `missing: 40`; the missing offsets (484–491) are confined to “single vs combined” diff pairs (domain/proto/type vs their pair/triple forms), indicating the combined‑form deltas still sit beyond the traced window end for the single‑arg cases.

These artifacts give a second, independent witness for where encoder writes land in the compiled blob for the network‑matrix specimens, but they do **not** resolve kernel semantics or eliminate the remaining join gaps for combined‑form diffs.

Additional follow‑ups:

- Added a secondary hardware breakpoint on `_sb_mutable_buffer_make_immutable`; stats now include `immutable_hits` and `immutable_buf`, but the immutable buffer pointer does not match the write‑event buffer addresses and the missing offsets remain unchanged.
- Added `out/network_matrix/encoder_write_record_map.json`, which maps trace windows to stride‑8 record boundaries (`within_record_offset` counts) using `out/network_matrix/index.json`. This provides a structural “which record bytes are touched” view without asserting semantics.

### What remains before promotion or reuse

The trace‑backed join is still partial/brittle. Before relying on these results outside this experiment (or dispersing tooling/artifacts into shared areas), complete the following:

- Tracer correctness hardening: classify breakpoint vs single‑step by Mach exception codes (no PC tolerance), log ring‑buffer drops/truncation, and require `unknown_break_hits == 0` so missing bytes can be treated as real evidence rather than logging artifacts.
- Close or bound the join gaps: either capture the missing offsets (484–491) via an additional writer breakpoint or mark them as explicitly inferred in the join outputs; update `check_trace_join.py` to consume witnessed vs inferred labeling so the check is non‑vacuous.
- Compile‑mode invariance: run a small matrix across file vs string and params on/off modes, confirm the join windows/hole ranges remain stable, and record the outcome here.
- Static↔dynamic linkage: include PC/LR (or a call‑site tag) in trace records so the write stream can be tied back to the encoder sites in `out/encoder_sites.json` without manual inference.
- Guardrail + promotion path: keep the experiment‑local guardrail (`check_trace_join.py`) as the drift gate, then only propose promotion after it is stable across multiple runs; any shared artifacts must go through validation → mapping generation → CARTON manifest with `world_id` and status declared as `partial`/`ok`.

### Promotion proposal (when you want to harden this join)

- Promote the join hypothesis summary into shared tooling only after another round of evidence (additional specimens or a second host baseline), then consider wiring the guardrail into `book/tests/` and updating shared decoder/oracle docs to cite the stable join.

## Phase B — artifacts and partial findings

- `out/encoder_sites.json` records a small set of encoder-side sites with addresses and evidence notes (partial):
  - `_emit` uses `_sb_mutable_buffer_write` to append bytes to the mutable buffer.
  - `_emit_network` emits three items (domain/type/proto) via `_emit` with widths {1,1,2} after padding to an 8-byte boundary when needed.
  - `_record_condition_data` threads emitted data into a per-op list/table (shape still under exploration).
  - The builder’s mutable buffer handle is consistently addressed at `builder+0xe98` across encoder helpers; `_compile` calls `_sb_mutable_buffer_make_immutable` on that handle.
- Join hypothesis summary: `out/network_matrix/join_hypotheses.json` (experiment-local scoring) with guardrail `check_network_join.py`.
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
  - `python3 book/evidence/experiments/field2-final-final/libsandbox-encoder/run_phase_a.py`
- Refresh Phase A network arg matrix (recompiles `sb/network_matrix/*.sb` and rewrites `out/network_matrix/*`):
  - `python3 book/evidence/experiments/field2-final-final/libsandbox-encoder/run_network_matrix.py`
  - `python3 book/evidence/experiments/field2-final-final/libsandbox-encoder/diff_network_matrix.py`
  - `python3 book/evidence/experiments/field2-final-final/libsandbox-encoder/join_network_matrix.py`
  - `python3 book/evidence/experiments/field2-final-final/libsandbox-encoder/analyze_network_join.py`
  - `python3 book/evidence/experiments/field2-final-final/libsandbox-encoder/check_network_join.py`
  - `python3 book/evidence/experiments/field2-final-final/libsandbox-encoder/oracle_network_matrix.py` (HISTORICAL)
  - `python3 book/tools/sbpl/oracles/network_matrix.py --manifest book/evidence/experiments/field2-final-final/libsandbox-encoder/sb/network_matrix/MANIFEST.json --blob-dir book/evidence/experiments/field2-final-final/libsandbox-encoder/out/network_matrix --out book/evidence/experiments/field2-final-final/libsandbox-encoder/out/network_matrix/oracle_tuples.json` (maintained oracle)

## Next steps

- Use the oracle output (`out/network_matrix/oracle_tuples.json`) and join artifacts (`out/network_matrix/join_records.jsonl`) as the acceptance criteria for any new Phase B “encoder-side structure” claim about where the `{1,1,2}` bytes land.
- With a stable join for single, pairwise, and triple forms (including proto high byte), revisit Phase B conclusions and only then propose minimal shared decode/mapping changes (role assignment, record boundaries) backed by these byte-level witnesses.
