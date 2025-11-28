# Vocab from Cache Experiment (Sonoma host)

Goal: extract Operation/Filter vocab tables (name ↔ ID) from the macOS dyld shared cache (Sandbox.framework/libsandbox payloads) and align them with decoder-derived op_count/op_table data from canonical blobs, producing real `ops.json` / `filters.json` for this host.

---

## 1) Setup and scope

- [x] Record host baseline (OS/build, kernel, SIP) in `ResearchReport.md`.
- [x] Inventory canonical blobs for alignment: `examples/extract_sbs/build/profiles/*.sb.bin`, `examples/sb/build/sample.sb.bin` (decoder op_count ~167).
- [x] Confirm existing partial vocab artifacts (`validation/out/vocab/ops.json`, `filters.json`) and metadata (`validation/out/metadata.json`).

Deliverables:
- `Plan.md`, `Notes.md`, `ResearchReport.md` in this directory.
- A script to extract Sandbox-related binaries from the dyld shared cache.

## 2) Cache extraction

- [x] Locate the dyld shared cache (`/System/Library/dyld/dyld_shared_cache_*`).
- [x] Use `dyld_shared_cache_util` (or equivalent) to extract Sandbox-related slices:
  - Sandbox.framework
  - libsandbox.dylib (if present)
- [x] Store extracted binaries under `book/experiments/vocab-from-cache/extracted/` with provenance notes (cache path, command used).

Deliverables:
- Extracted binaries and a short note in `Notes.md` describing commands used and any issues.

## 3) Name harvesting

- [x] Write a small parser (Python) to scan extracted binaries for operation/filter name tables:
  - Search for known operation strings (`file-read*`, `mach-lookup`, `network-outbound`) to anchor tables.
  - If symbol-linked arrays exist, preserve ordering; otherwise, infer ordering via contiguous strings/offsets.
- [x] Count recovered names; compare to decoder `op_count` from canonical blobs (target ~167 on this host).
- [x] If filter names are discoverable, repeat for filter tables.

Deliverables:
- `harvest.py` (or similar) that emits candidate name lists with offsets/order.
- Intermediate JSON with recovered names and inferred ordering.

## 4) ID alignment

- [x] Align harvested names with decoder op_table/op_count:
  - Ensure name count matches `op_count`.
  - Spot-check by compiling single-op SBPL (from op-table-operation) and verifying op_table index matches inferred ID.
- [x] Emit `validation/out/vocab/ops.json` / `filters.json` with:
  - `status: ok` (or `partial` if only names),
  - metadata (host, build, format_variant, sources, content hash),
  - entries `{name, id, provenance}`.

Deliverables:
- Updated vocab artifacts with real entries and provenance.

## 5) Alignment and propagation

- [ ] Rerun `op-table-vocab-alignment` to fill `operation_ids` and `vocab_version`.
- [ ] Note bucket↔ID relationships in `ResearchReport.md` here and in op-table-operation/op-table-vocab-alignment reports.

Deliverables:
- Updated alignment file with IDs and vocab hash/version.
- Notes/report entries summarizing bucket-to-ID findings (scoped to this host).

## 6) Open questions / risks

- If cache extraction fails or yields obfuscated tables, fall back to runtime name observation (semantic probes) as a secondary path.
- Filter vocab may remain partial if tables are not obvious; mark `filters.json` status accordingly.
- Keep everything versioned by OS/build; do not guess IDs if counts/order don’t line up.
