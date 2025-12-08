## Purpose

Map how this host’s `libsandbox` encodes filter arguments into the `field2` u16 in compiled profiles and align those encodings with the Filter Vocabulary Map (`book/graph/mappings/vocab/filters.json`, status: ok). The kernel is treated as consuming a raw u16; the focus here is purely on userland emission.

## Baseline & scope

- Host: macOS 14.4.1 (23E224), Apple Silicon, SIP enabled (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)`).
- Inputs: `book/api/sbpl_compile`, `book/api/decoder`, trimmed `libsandbox` slice under `book/graph/mappings/dyld-libs/`.
- Out of scope: runtime `sandbox_apply` or kernel-side interpretation (covered by `field2-filters`).

## Plan & execution log

- Phase A — SBPL→blob matrix (encoder output view): matrix v1 (regex-free) compiled via `sbpl_compile`; nodes parsed via `profile_ingestion` + custom helper with local tag overrides; table emitted to `out/matrix_v1_field2_encoder_matrix.json`. Tag2/tag3 treated as meta/no payload; tag10 resolved header-aligned layout (tag=h0.low, filter_id=h1, payload=h2) via full-context socket-domain 2→30 variants; matrix now exposes both `filter_id_raw` and `payload_raw` for tag10. Tag8 left filter-id-only.
- Phase B — libsandbox internals (encoder implementation view): serializer RE in progress; buffer at builder+0xe98 confirmed; `_emit_network` ordering/widths noted; finalize path to `__sandbox_ms` and explicit store offsets still pending.

## Evidence & artifacts

- `sb/matrix_v1.sb` (regex-free baseline); `sb/matrix_v2.sb` (arg-variance probe; decode currently skewed to tag6/5; not used for conclusions).
- `sb/matrix_v1_domain2.sb`, `sb/matrix_v1_domain30.sb` (full-context copies of matrix_v1 with socket-domain 2 vs 30) used to confirm tag10 payload offset.
- `out/tag_layout_overrides.json` (local, staged) for tags 2/3/8/10; tag10 resolved: tag=h0.low, filter_id=h1, payload=h2 (header-aligned).
- `out/matrix_v1.sb.bin`, `out/matrix_v1.inspect.json`, `out/matrix_v1.op_table.json`, `out/matrix_v1_field2_encoder_matrix.json` (Phase A table with tag2/3 excluded; tag10 includes payload).
- `out/matrix_v2.sb.bin`, `out/matrix_v2.inspect.json`, `out/matrix_v2_field2_encoder_matrix.json` (decode skewed; not relied on).
- `dump_raw_nodes.py` (heuristic node dumper used in Phase B; now also supports `--header` to slice using `inspect_profile`’s `nodes_start`/`nodes_len`). For `matrix_v1.sb.bin` it locates a 12-byte-stride node block at [0,480) and shows the seven records closest to the literal pool as:
  - 396: [0, 0, 2560, 21, 10, 1]
  - 408: [3328, 6, 9, 2, 3072, 1]
  - 420: [9, 3, 2816, 2, 9, 10]
  - 432: [1536, 11, 9, 5, 1792, 16]
  - 444: [9, 10, 4352, 5, 9, 7]
  - 456: [4608, 8, 9, 10, 256, 0]
  - 468: [9, 10, 1281, 0, 0, 0]
- Pending: `out/encoder_sites.json`.

## Blockers / risks

- Phase B is expected to be partial/brittle unless encoder patterns are obvious; no promotion to `book/graph/mappings/*` without corroboration.

## Phase B notes (in-progress)

- Serializer context (manual RE): in the “bytecode_output.c” region (`0x183d01f*`), the compiler sets `x22 = builder + 0xe98` and uses that pointer for `_sb_mutable_buffer_set_minimum_size` and `_sb_mutable_buffer_write`. The same base+0xe98 is passed through `_emit`, `_emit_instruction`, `_emit_pattern`, etc., so offset 0xe98 is the mutable buffer handle for the compiled profile. `_encode_address` also touches `[ctx, #0xe98]` (on overflow it stores an error there), reinforcing that 0xe98 is the buffer field in the builder.
- Finalize/hand-off to `__sandbox_ms` still to be confirmed: need to follow the builder’s finalize path (post `_sb_mutable_buffer_make_immutable`) up to the caller that packages `buf,len` for `__sandbox_ms` to cement “this is the blob we decode”.
- Next mapping task: in `_emit_network`/`_record_condition_data`, watch the write cursor around the three `_emit` calls (domain/type/proto), derive their byte offsets, and align those emitted bytes to the tag10 halfwords we dumped (offsets 398–422) to confirm the payload field (currently h2).
- `_emit_network` disasm skim: pads to 8-byte boundary when needed (`[ctx+8]->0x18 & 7`, then `_emit` zeros of size `(8 - rem)`), calls `_get_current_data_address`, then emits three items in order via `_emit` with sizes {1,1,2} from the arg struct (`ldrb [arg+#1]`, `ldrb [arg]`, `ldrh [arg+#2]`). `_emit` itself writes byte-by-byte to the mutable buffer (`ldr x8, [ctx,#0x8]`, `_sb_mutable_buffer_write(x8, cursor, sp_bytes)`), asserting that the value fits in the requested width (`value < 0x100` for size 1). This gives a concrete “domain/type/proto” write order and confirms the buffer path used by per-filter emitters.
- `_record_condition_data` is a compact linker: it decrements `c->ec_free_count`, uses that index to write a 0x18-byte entry `{data_ptr, data_len?, filter_id}` into the `ec_data` array, and threads the entry into a per-op linked list via `[ctx + (tag?)*8 + 0x20]`. This is likely how filter ID + data offset get paired before serialization.
- Tooling note: `inspect_profile` now emits `nodes_raw` (offset, tag byte, raw bytes, halfwords) to make per-record layouts explicit. `dump_raw_nodes.py` can also read `nodes_start`/`nodes_len` from the adjacent `*.inspect.json` via `--header` (using `nodes_raw` count/size). Phase A matrix now emits both `filter_id_raw` and `payload_raw` for payload-bearing tags (tag10: tag=h0.low, filter_id=h1, payload=h2 confirmed via matrix_v1_domain2/30).
- Encoder sites logged in `out/encoder_sites.json`: `_emit` (bytes→mutable buffer via `_sb_mutable_buffer_write`), `_emit_network` (domain/type/proto via three `_emit` calls), `_record_condition_data` (stores data_ptr/len/index into per-op list), and the mutable buffer handle at builder+0xe98 (partial).
- Finalize path: `_compile` calls `_sb_mutable_buffer_make_immutable` on the builder’s mutable buffer (builder+0xe98) at 0x183ced36c and stores the resulting `sb_buffer*`; explicit handoff of that immutable buffer to `__sandbox_ms` remains to be traced.

## Experiment Status

This experiment is now **CLOSED**.

- AIM achieved for this iteration: mapped libsandbox’s encoding of filter arguments into the PolicyGraph u16 payload (“field2”) on Sonoma 14.4.1, aligned tag10 with the Filter Vocabulary Map, and validated the layout via header-aligned decoding and targeted SBPL probes.
- Phase A: frozen with header-aligned parsing; tag2/tag3 classified as meta/no-payload; tag10 resolved (tag = h0.low, filter_id = halfword1, payload = halfword2); `matrix_v1_field2_encoder_matrix.json` exposes both `filter_id_raw` and `payload_raw` for payload-bearing tags. Tag8 is intentionally left filter-id-only.
- Phase B: inside `libsandbox.1.dylib`, encoder sites identified (`_emit`, `_emit_network`, `_record_condition_data`, builder+0xe98 mutable buffer, `_sb_mutable_buffer_make_immutable` in `_compile`). It is architecturally established that `libsystem_sandbox` compiles via `libsandbox` and then calls `__sandbox_ms`; the detailed function-pointer wiring and sb_buffer→(ptr,len)→syscall glue are deferred.
- Any further work on `libsystem_sandbox` glue (dynamic resolution in `sandbox_init*`, sb_buffer unpacking, syscall argument packing) is explicitly **out of scope** for `libsandbox-encoder` and will be handled in a follow-on experiment.

## Artifacts and Tooling Persistence Plan

The `libsandbox-encoder` experiment is CLOSED, but several artifacts and tools are promoted as reusable infrastructure and canonical references for Sonoma 14.4.1:

- **Tag layouts and encoder mapping**
  - `book/experiments/libsandbox-encoder/out/tag_layout_overrides.json`:
    - Source of truth for tag10 layout on this host (tag = h0.low, filter_id = halfword1, payload = halfword2, stride 12).
    - Tag2/tag3 explicitly marked meta/no-payload.
    - Tag8 currently filter-id-only (payload unresolved by design).
  - `book/experiments/libsandbox-encoder/out/matrix_v1_field2_encoder_matrix.json`:
    - Baseline SBPL→PolicyGraph encoder matrix for this host, exposing both `filter_id_raw` and `payload_raw` for payload-bearing tags.

- **Tools**
  - `book/experiments/libsandbox-encoder/run_phase_a.py`:
    - Reference implementation for compiling SBPL, decoding PolicyGraph nodes, and emitting encoder matrices using tag-specific layouts.
  - `book/experiments/libsandbox-encoder/build_tag_field_summary.py`:
    - Helper for summarizing tag roles and field usage across matrices.
  - `book/experiments/libsandbox-encoder/dump_raw_nodes.py`:
    - Header-aligned node dumper using `nodes_raw` (record size × count); canonical way to inspect raw 12-byte PolicyGraph records for this baseline.
  - `book/api/inspect_profile` (modified for this experiment):
    - Emits `nodes_raw` and trims the +3-byte tail for Sonoma 14.4.1 profiles; this behavior should be treated as the baseline for future experiments relying on PolicyGraph decoding.

- **Encoder site mapping**
  - `book/experiments/libsandbox-encoder/out/encoder_sites.json`:
    - Catalog of encoder-related functions in `libsandbox.1.dylib`:
      - `_emit`, `_emit_network`, `_record_condition_data`, builder+0xe98 mutable buffer, `_sb_mutable_buffer_make_immutable` in `_compile`.
    - Serves as the starting point for follow-on experiments (e.g., `sandbox-init-params`) that need to reason about how compiled profiles are formed before being handed to `libsystem_sandbox` and `__sandbox_ms`.

### Usage in future work

- Future experiments (including `book/experiments/sandbox-init-params/`) SHOULD:
  - Treat `tag_layout_overrides.json` and `matrix_v1_field2_encoder_matrix.json` as **read-only baselines** for Sonoma 14.4.1 field2 behavior.
  - Reuse `inspect_profile` and `dump_raw_nodes.py` for header-aligned node inspection, rather than re-inventing slicing heuristics.
  - Reference `encoder_sites.json` when mapping higher-level control flows (e.g., `sandbox_init_with_parameters` paths) back to `libsandbox` encoder internals.

- Any changes to these artifacts should be made via new experiments or versioned copies, not by mutating the closed `libsandbox-encoder` outputs.

## Next steps

- Continue Phase B disassembly: confirm buffer finalize path into `__sandbox_ms`; tie `_emit_network`/`_record_condition_data` offsets to the tag10 payload slot for a code-level provenance.
- Optional follow-up: if needed later, resolve tag8 payload via the same “vary one arg” header-aligned method; currently treated as filter-id-only.
