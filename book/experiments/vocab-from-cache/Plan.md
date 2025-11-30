# Vocab from Cache Experiment (Sonoma host)

Goal: extract Operation/Filter vocab tables (name ↔ ID) from the macOS dyld shared cache (Sandbox.framework/libsandbox payloads) and align them with decoder-derived op_count/op_table data from canonical blobs, producing real `ops.json` / `filters.json` for this host.

Status: Complete — extracted material deleted (trimmed copies retained under `book/graph/mappings/dyld-libs/`).

---

## 1) Setup and scope

**Done**

- Recorded host baseline (OS/build, kernel, SIP) in `ResearchReport.md`.
- Inventoried canonical blobs for alignment (system profiles plus `sample.sb.bin`).
- Confirmed vocab artifacts and static metadata under `book/graph/mappings/vocab` and `validation/out/metadata.json`.

**Upcoming**

- None for this section.

Deliverables:
- `Plan.md`, `Notes.md`, `ResearchReport.md` in this directory.
- A script to extract Sandbox-related binaries from the dyld shared cache.

## 2) Cache extraction

**Done**

- Located the dyld shared cache and extracted Sandbox-related slices (Sandbox.framework, libsandbox) into `extracted/` with provenance in `Notes.md`.

**Upcoming**

- None for this section.

Deliverables:
- Extracted binaries and a short note in `Notes.md` describing commands used and any issues.

## 3) Name harvesting

**Done**

- Implemented Python harvesters to scan extracted binaries for operation and filter name tables, using symbol-linked arrays where available.
- Counted recovered names and compared them to decoder op_count; confirmed 196 operations and 93 filters.

**Upcoming**

- None for this section.

Deliverables:
- `harvest.py` (or similar) that emits candidate name lists with offsets/order.
- Intermediate JSON with recovered names and inferred ordering.

## 4) ID alignment

**Done**

- Aligned harvested names with decoder op_table/op_count and spot-checked using single-op SBPL profiles.
- Emitted `book/graph/mappings/vocab/ops.json` and `filters.json` with `status: ok`, host/build metadata, and per-entry provenance.

Deliverables:
- Updated vocab artifacts with real entries and provenance.

## 5) Alignment and propagation

**Done**

- Reran `op-table-vocab-alignment` to fill `operation_ids` and `vocab_version`, then updated alignment artifacts.
- Added a lightweight sanity check (`check_vocab.py`) to assert vocab status and counts.
- Noted key bucket↔Operation ID relationships (e.g., mach-lookup in buckets {5,6}) in this ResearchReport and in the op-table experiments.

**Upcoming**

- Refresh alignment and bucket snapshots only if vocab artifacts are regenerated for a new host/build.

Deliverables:
- Updated alignment file with IDs and vocab hash/version.
- Notes/report entries summarizing bucket-to-ID findings (scoped to this host).

## 6) Open questions / risks

- If cache extraction fails or yields obfuscated tables, fall back to runtime name observation (semantic probes) as a secondary path.
- Filter vocab may remain partial if tables are not obvious; mark `filters.json` status accordingly.
- Keep everything versioned by OS/build; do not guess IDs if counts/order don’t line up.
