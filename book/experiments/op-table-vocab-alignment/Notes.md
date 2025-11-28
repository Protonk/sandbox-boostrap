# Op-table ↔ Operation Vocabulary Alignment – Notes

1. **Initialization (Chat agent, 2025-11-27)**
   - Created experiment directory `book/experiments/op-table-vocab-alignment/` alongside `node-layout` and `op-table-operation`.
   - Added initial `Plan.md` laying out setup, vocabulary hookup, alignment, interpretation, and turnover steps.
   - Created `ResearchReport.md` skeleton with motivation, scope, and planned structure; no code or analysis has been run yet.
   - Intent is to treat this experiment as a bridge between existing bucket-focused work and the vocabulary-mapping validation cluster, without assuming responsibility for full vocab extraction.

2. **Artifact inventory and placeholder alignment (Chat agent, 2025-11-29)**
   - Confirmed presence of upstream artifacts: `node-layout/out/summary.json`, `op-table-operation/out/summary.json`, and `op_table_map.json`.
   - Checked vocabulary outputs under `book/graph/concepts/validation/out/vocab/` and found the directory empty; noted dependency on the vocabulary-mapping tasks in `validation/tasks.py`.
   - Generated a placeholder alignment artifact `out/op_table_vocab_alignment.json` from `op-table-operation/out/summary.json`, capturing per-profile SBPL ops, op-table indices, and operation_count with `operation_ids` left null until a vocab file exists.

3. **Placeholder vocab artifacts and alignment update (Chat agent, 2025-11-29)**
   - Created placeholder `book/graph/concepts/validation/out/vocab/ops.json` and `filters.json` (status `unavailable`, IDs unknown) using host metadata from `validation/out/metadata.json` to unblock downstream consumers; real vocab extraction remains outstanding.
   - Updated `out/op_table_vocab_alignment.json` to record `vocab_present=true`, `vocab_status=unavailable`, and `vocab_version` set to the placeholder timestamp; `operation_ids` remain null pending a real vocabulary map.

4. **Contract and versioning notes (Chat agent, 2025-11-29)**
   - Recorded expected JSON contract for future `ops.json` / `filters.json` in `ResearchReport.md`, including OS/build provenance and a vocab content hash for versioning.
   - Captured host baseline (macOS 14.4.1 / 23E224, kernel 23.4.0, SIP enabled) in `ResearchReport.md`.

5. **Attempted vocab generation (Chat agent, 2025-11-29)**
   - Ran `book/examples/extract_sbs/run-demo.sh` to regenerate system profile blobs (airlock.sb.bin, bsd.sb.bin) under `examples/extract_sbs/build/profiles/`.
   - Ran `book/examples/sb/run-demo.sh` after fixing an import path in `compile_sample.py` (changed to `book.graph.concepts.validation`); generated `examples/sb/build/sample.sb.bin`.
   - Investigated `validation/out/static/system_profiles.json` outputs; ingestion marks format as `unknown-modern` with empty op_table lengths, leaving no visible vocabulary data to extract.
   - Searched repo for existing vocab extraction tooling; none present beyond placeholders. Attempted to locate `libsandbox.dylib` for symbol introspection; paths not found via `find` within time limits.
   - Conclusion: without a decoder for the modern compiled format or a known vocab table source, real `ops.json` / `filters.json` cannot be generated on this host. Placeholder vocab remains; alignment still lacks operation IDs.

6. **Decoder-aware alignment prep (Chat agent, 2025-11-30)**
   - Reviewed the new decoder-backed outputs from sibling experiments and updated `Plan.md`/`ResearchReport.md` to spell out how future vocab extraction should consume decoder slices plus static metadata.
   - Kept alignment artifacts unchanged (still placeholders) but clarified that a future vocabulary pipeline should read canonical blobs via `decoder.decode_profile_dict` and attach OS/build hashes to `ops.json`/`filters.json`.
   - No new vocab data yet; alignment remains bucket-only with `operation_ids=null`, but the contract for filling them is now more explicit.

3. **Partial vocab scaffold (Chat agent, 2025-11-28)**
   - Added `book/graph/concepts/validation/vocab_extraction.py` to collect decoder-derived metadata from canonical blobs and emit partial vocab artifacts even when names/IDs are unavailable.
   - Ran the script; new `out/vocab/ops.json` / `filters.json` now include host metadata, decoder-derived `op_count`/`op_table` entries for system/sample blobs, and `status: partial` instead of `unavailable`.
   - Refreshed `out/op_table_vocab_alignment.json` to record the new vocab version (`generated_at`) and `vocab_status: partial`; `operation_ids` remain null until real vocab extraction is implemented.

7. **Alignment refreshed with real vocab + filters (2025-12-03)**
   - Updated `update_alignment.py` to ingest `filters.json` alongside `ops.json` and to copy per-profile filters from the op-table-operation summaries.
   - Regenerated `out/op_table_vocab_alignment.json`; records now include `filters` and `filter_ids`, and `operation_ids` are populated from the harvested vocab.
