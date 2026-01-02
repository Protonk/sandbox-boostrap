# Zero-knowledge libsandbox encoder mapping

> A positive result from robot science

## Summary

This experiment asked a narrower, complementary question to the earlier “zero-knowledge field2” run ([status/pair-programming/Pairing-field2-hunt.md](status/pair-programming/Pairing-field2-hunt.md)). Instead of chasing what the kernel *does* with the third 16-bit node slot (`field2`), we asked how **libsandbox** on Sonoma 14.4.1 ([world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world.json)](world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world.json))) actually *fills* that slot when it compiles SBPL into a profile blob.

On this host, decoded PolicyGraph nodes have a familiar shape: a tag byte and a handful of 16-bit fields, one of which is treated in this project as `field2 = filter_arg_raw` (see [book/substrate/Concepts.md](book/substrate/Concepts.md) for PolicyGraph terminology). Earlier work showed that low values in this slot line up with a Filter Vocabulary Map ([book/graph/mappings/vocab/filters.json](book/graph/mappings/vocab/filters.json)), while a handful of high values in rich profiles remained unexplained—and that the kernel does *not* implement the old “row of structs + hi/lo bitfields” story.

Here, we shifted the focus up a layer. Using SBPL probes, a refined profile decoder, and disassembly of `libsandbox.1.dylib`, the agents worked out how filter IDs and arguments are laid out in the node records for a key tag (tag10) on this Sonoma baseline. The result is a concrete, byte-level layout for tag10—tag = low byte of halfword0, filter ID in halfword1, payload in halfword2—backed by reproducible SBPL differences (socket-domain 2→30) and a catalog of encoder sites in libsandbox. The syscall side in `libsystem_sandbox` is left as architecture-level context for a follow-on experiment.

Where the earlier experiment ended with a strong *negative* result (“the old Blazakis-style node array story is false here”), this one ends with a constrained *positive* mapping: we now know, on this host, which halfword in tag10 is the filter ID, which halfword is the encoded argument, and which upstream functions in libsandbox write them.

## Report

### Background and aim

In the project’s Sonoma baseline (14.4.1, 23E224, Apple Silicon), decoded policy graphs show each PolicyGraph node as a small fixed record with:

* a tag byte, and
* several 16-bit fields, one of which is modeled as `field2 = filter_arg_raw` (for tag10 on this host: tag = low byte of halfword0, `field2` corresponds to halfword2, and halfword1 carries the filter ID).

Low `field2` values are already mapped onto a Filter Vocabulary Map ([book/graph/mappings/vocab/filters.json](book/graph/mappings/vocab/filters.json)) covering path filters, socket-domain, iokit filters, mach names, etc., and earlier “zero-knowledge” work ([status/pair-programming/Pairing-field2-hunt.md](status/pair-programming/Pairing-field2-hunt.md)) showed that:

* high `field2` values cluster in specific tails and mixed profiles,
* the kernel treats this operand as a plain u16, and
* there is no evidence of simple hi/lo bitfield semantics or a backing node array in the kernel.

The aim here was deliberately narrower and compiler-side:

> For this Sonoma host, determine how **libsandbox** encodes filter arguments into the PolicyGraph node payload and align that encoding with the Filter Vocabulary Map, treating the kernel as a black box that consumes a raw u16.

The experiment was split into:

* **Phase A:** SBPL → compiled blob → decoded PolicyGraph; and
* **Phase B:** libsandbox internals (TinyScheme primitives, emit/serializer path, builder buffer).

### Phase A: SBPL → PolicyGraph layout

The codex agent scaffolded `book/experiments/field2-final-final/libsandbox-encoder/` with `Plan.md`, `Report.md`, `Notes.md` and a pair of directories `sb/` and `out/`. The core work in Phase A was to cleanly relate SBPL filters and arguments to node fields in decoded profiles, then freeze a layout that other experiments can treat as input (see [book/experiments/field2-final-final/libsandbox-encoder/Report.md](book/experiments/field2-final-final/libsandbox-encoder/Report.md) for the experiment-local view).

Key steps:

1. **Matrix SBPL and initial decoding attempts**

   * Authored `sb/matrix_v1.sb`, a regex-free SBPL “matrix” over:

     * `file-read*`, `mach-lookup`, `network-outbound`, `iokit-open`,
     * filter shapes: literal/subpath path filters, socket domain/type/proto, iokit class/property, mach names.
   * Implemented `run_phase_a.py` ([book/experiments/field2-final-final/libsandbox-encoder/run_phase_a.py](book/experiments/field2-final-final/libsandbox-encoder/run_phase_a.py)) to:

     * compile SBPL with `book.api.profile_tools compile`,
     * decode compiled blobs via the project’s profile decoder,
     * emit a per-node table keyed by tag-specific layouts: `(op, filter_name, SBPL arg, tag, filter_id_raw, payload_raw)` for payload-bearing tags (tag10), and filter-id-only rows for others. Tag2/tag3 were excluded as meta. See [book/experiments/field2-final-final/libsandbox-encoder/out/matrix_v1_field2_encoder_matrix.json](book/experiments/field2-final-final/libsandbox-encoder/out/matrix_v1_field2_encoder_matrix.json).

   Early runs revealed problems: tiny sanity profiles and the matrix were dominated by tags 2 and 3 with uniform fields (e.g., `[2,2,2,2,0]`), and `field2_raw` collapsed to a few IDs regardless of SBPL arguments. That indicated we were slicing the node block or interpreting fields incorrectly.

2. **Header-aligned node slicing and tag roles**

   The agents hardened the decoding pipeline, using the project’s profile inspection/decoder tooling (now under `book/api/profile_tools/`) as the ground truth:

   * **profile_tools inspect/decoder** (formerly `inspect_profile`) was extended to:

     * emit `nodes_raw` (offset, tag byte, raw bytes, halfwords),
     * normalize the nodes section by trimming a consistent +3-byte tail and using `record_size × node_count` as the canonical `nodes_len` (12-byte records on this host). Example: [book/experiments/field2-final-final/libsandbox-encoder/out/matrix_v1.inspect.json](book/experiments/field2-final-final/libsandbox-encoder/out/matrix_v1.inspect.json).
   * **dump_raw_nodes.py** ([book/experiments/field2-final-final/libsandbox-encoder/dump_raw_nodes.py](book/experiments/field2-final-final/libsandbox-encoder/dump_raw_nodes.py)) gained `--header` and `--stride` modes:

     * it now uses `nodes_start` plus `len(nodes_raw) × record_size` to dump header-aligned records with a fixed 12-byte stride.
   * Mining `tag_inventory` and tiny profiles showed:

     * tag2 and tag3 have stable, argument-independent structure and appear as scaffolding/meta nodes,
     * they were reclassified as meta/no-payload and excluded from the encoder matrix.

   With these changes, Phase A could rely on a canonical view of the node block: on this host, node records are 12 bytes (6 halfwords), with `tag = low byte of halfword0`.

3. **Resolving tag10 (filter ID vs payload)**

   Once slicing was stable, the agents focused on **tag10**, the main payload-bearing tag in `matrix_v1` ([book/experiments/field2-final-final/libsandbox-encoder/sb/matrix_v1.sb](book/experiments/field2-final-final/libsandbox-encoder/sb/matrix_v1.sb)):

   * Header-aligned dumps showed:

     * 33 nodes for `matrix_v1`, with 28 tag10 nodes.
     * For tag10, halfwords across the matrix took values consistent with known filter IDs `{6,8,9,10}` and a small set of other IDs, but `matrix_v1` itself had only one argument per filter, so no intra-filter variation.

   To break the symmetry and separate filter ID from payload, the codex agent:

   * Cloned the full `matrix_v1` SBPL into two variants that differed only in `socket-domain`:

     * domain 2 vs domain 30,
     * all other clauses identical so tag10 would still be emitted.
   * Compiled and decoded both ([book/experiments/field2-final-final/libsandbox-encoder/sb/matrix_v1_domain2.sb](book/experiments/field2-final-final/libsandbox-encoder/sb/matrix_v1_domain2.sb), `…/matrix_v1_domain30.sb`), then compared header-aligned tag10 nodes via [book/experiments/field2-final-final/libsandbox-encoder/out/matrix_v1.sb.inspect.json](book/experiments/field2-final-final/libsandbox-encoder/out/matrix_v1.sb.inspect.json).

   In those paired profiles, a tag10 node appeared where:

   * halfword1 remained constant with value 10 (socket-domain’s filter ID), and
   * halfword2 changed from 2 → 30 as the SBPL arg changed.

   From this, the experiment fixed the tag10 layout for this Sonoma baseline (recorded in [book/experiments/field2-final-final/libsandbox-encoder/out/tag_layout_overrides.json](book/experiments/field2-final-final/libsandbox-encoder/out/tag_layout_overrides.json)):

   * **Tag10 layout (Sonoma 14.4.1, arm64)**

     * tag = low byte of halfword0
     * filter_id = halfword1
     * payload (e.g., socket-domain) = halfword2
     * stride = 12 bytes (6 halfwords).

   This was recorded in [book/experiments/field2-final-final/libsandbox-encoder/out/tag_layout_overrides.json](book/experiments/field2-final-final/libsandbox-encoder/out/tag_layout_overrides.json) (tag10 marked ok; tag2/3 meta; tag8 left filter-id-only).

4. **Freezing the Phase A matrix**

   `run_phase_a.py` was updated to consult tag-specific layouts:

   * It now emits both `filter_id_raw` and `payload_raw` for payload-bearing tags (tag10) in [book/experiments/field2-final-final/libsandbox-encoder/out/matrix_v1_field2_encoder_matrix.json](book/experiments/field2-final-final/libsandbox-encoder/out/matrix_v1_field2_encoder_matrix.json).
   * Tag2/tag3 are excluded as meta; tag8 contributes only filter IDs by design (see [book/experiments/field2-final-final/libsandbox-encoder/out/tag_layout_overrides.json](book/experiments/field2-final-final/libsandbox-encoder/out/tag_layout_overrides.json)).

At this point Phase A was declared **frozen**:

   * Node slicing is header-aligned and normalized.
   * Tag10’s layout is fully resolved and encoded in `tag_layout_overrides.json`.
   * The encoder matrix gives a concrete SBPL→PolicyGraph view of how libsandbox encodes filter ID and payload for tag10 on this host.

### Phase B: libsandbox encoder and serializer

With the PolicyGraph view stable, Phase B asked how libsandbox’s compiler produces those node records. This phase deliberately stops at the `libsandbox` / `libsystem_sandbox` boundary; the syscall glue in `libsystem_sandbox` ([book/graph/mappings/dyld-libs/usr/lib/system/libsystem_sandbox.dylib](book/graph/mappings/dyld-libs/usr/lib/system/libsystem_sandbox.dylib)) is reserved for a follow-on experiment.

Key findings in `libsandbox.1.dylib` ([book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib](book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib), recorded in [book/experiments/field2-final-final/libsandbox-encoder/out/encoder_sites.json](book/experiments/field2-final-final/libsandbox-encoder/out/encoder_sites.json) and [book/experiments/field2-final-final/libsandbox-encoder/Report.md](book/experiments/field2-final-final/libsandbox-encoder/Report.md)):

* **Encoder and serializer sites** (catalogued in [book/experiments/field2-final-final/libsandbox-encoder/out/encoder_sites.json](book/experiments/field2-final-final/libsandbox-encoder/out/encoder_sites.json))

  * `_emit`:

    * Handles writing bytes/halfwords into a mutable buffer, via `_encode_address` and `_sb_mutable_buffer_write`.
  * `_emit_network`:

    * Emits `network-outbound` arguments by calling `_emit` three times for domain/type/proto, with widths/order 1/1/2.
  * `_record_condition_data`:

    * Captures `(data_ptr, len)` for argument blobs and threads them into per-op lists, linking filters to data regions in the mutable buffer.
  * Builder struct:

    * Holds a central mutable buffer at `builder+0xe98`; all encoder writes target this buffer.
  * `_sb_mutable_buffer_make_immutable` in `_compile`:

    * Called on `builder+0xe98` at finalize; produces an immutable `sb_buffer*` that represents the compiled profile blob.

 * **Finalize and boundary**

  * `_compile` builds the profile using the builder, then calls `_sb_mutable_buffer_make_immutable` on `builder+0xe98` and returns the resulting `sb_buffer*`.
  * `_sandbox_compile_file` / `_sandbox_compile_named` call `_compile` and return that `sb_buffer*` in `x0` to their caller.

 This gives a clean internal chain:

> SBPL / TinyScheme primitives → `_emit` / `_emit_network` / `_record_condition_data` → builder’s mutable buffer at +0xe98 → `_sb_mutable_buffer_make_immutable` → immutable `sb_buffer*` = compiled profile blob.

 The syscall glue is deliberately left for a follow-on experiment:

  * In `libsystem_sandbox.dylib`, `_sandbox_init_with_parameters` dynamically resolves `"sandbox_compile_string"`, `"sandbox_compile_named"`, `"sandbox_compile_file"` and calls through function pointers, and `__sandbox_ms` stubs exist.
  * It is architecturally clear that `libsystem_sandbox` calls libsandbox’s compile entry points, receives an `sb_buffer*`, and ultimately passes a `(ptr,len)` to `__sandbox_ms`.
  * Fully unwinding the function-pointer dispatcher and argument packing is non-trivial and, as noted above, was explicitly deferred to a new experiment (`book/experiments/sandbox-init-params/`); libsandbox-encoder is closed at this boundary.

### Closure and follow-on

By the end of this run, the `libsandbox-encoder` experiment had achieved its AIM on this host: it established a concrete, header-aligned record layout for tag10 (including filter ID and payload slots), verified that this layout matches libsandbox’s behavior under controlled SBPL arg variation, and catalogued encoder and serializer sites in libsandbox and the builder→immutable `sb_buffer*` path. Along the way it hardened shared tooling—profile inspection/decoder tooling (now `book/api/profile_tools/`), `dump_raw_nodes.py`, `run_phase_a.py`, `build_tag_field_summary.py`, and the baseline artifacts under `book/experiments/field2-final-final/libsandbox-encoder/out/`—and drew a clean boundary to a new experiment for `libsystem_sandbox` glue.

Compared to the earlier “zero-knowledge field2” run, which established a negative result in the kernel (“no hidden node arrays, no hi/lo bitfields”), this experiment gives a positive compiler-side map: how libsandbox actually lays down filter IDs and arguments in the node records we decode. Together, they narrow the search space for any future attempts to explain the remaining “mystery” field2 values on this Sonoma host, and they do so with reusable code, artifacts, and explicit stopping rules rather than just an evolving folk story.

Taken together, these two experiments also demonstrate something about the method itself: it is not just capable of stumbling onto negative results that a “monkeys at a typewriter” process might eventually find by brute force; the same structured, scaffolded path—fixed substrate ([book/substrate/Orientation.md](book/substrate/Orientation.md), [book/substrate/Concepts.md](book/substrate/Concepts.md)), paired agents ([status/pair-programming/Pairing-field2-hunt.md](status/pair-programming/Pairing-field2-hunt.md), this report), explicit stopping rules, and artifact-first reporting—can also produce a *positive* mapping that goes beyond what is written in the current public canon. The field2 experiment showed how this loop can rigorously close down an attractive but wrong story; the libsandbox-encoder experiment shows that, without changing the basic workflow, the same loop can climb one step ahead of existing research and fix new concrete facts (like the tag10 layout on this host) into the shared record.
