# SBPL ↔ Graph ↔ Runtime Triples

## Goal

Produce small “golden” triples (SBPL source, decoded graph, runtime probe outcomes) for a few canonical semantic shapes. Each triple should let us point from SBPL → compiled graph → observed allow/deny, exercising the semantic cluster and tying into static format and vocab.

## Scope

- Profiles: tiny SBPLs covering allow-all/deny-all, deny-except, single-filter allow, metafilter (require-any/all/not), and a simple param example.
- Outputs: compiled blobs, decoded graph snippets (node IDs, filters, decisions), runtime probe logs (ndjson), and a manifest linking them.
- Location: artifacts under `book/graph/mappings/runtime/` (or sibling) once stable; scratch outputs in `out/`.

## Steps

1) **Author profiles**
   - Write minimal SBPL files for each shape under this directory (e.g., `allow_all.sb`, `deny_except_tmp.sb`, `metafilter_any.sb`, `param_path.sb`).
   - Keep operations simple (file-read*, file-write*) and filters small (literal/subpath).

2) **Compile and decode**
   - Use existing ingestion (`book/graph/concepts/validation/profile_ingestion.py`) to parse compiled blobs and emit JSON with op-table, nodes, and literals.
   - Extract node IDs/filters/decisions relevant to the probes into a concise summary per profile.

3) **Run runtime probes**
   - Reuse/extend a harness (runner/reader or `book/api/SBPL-wrapper/wrapper --blob`) to execute a few file probes per profile, logging operation, path, exit, and errno to ndjson.
   - For environments where sandbox-apply is blocked, note the failure and prepare to rerun in a SIP-relaxed context.
   - Status: runtime probes run via `sandbox_runner`/`sandbox_reader` for these profiles; wrapper-based blob runs are available via the runtime-checks harness.

4) **Link triple**
   - Build a manifest that ties SBPL → compiled blob → decoded nodes → runtime outcomes for each profile, with OS/build metadata.

## Done criteria

- At least 3 profiles with complete triples (source, decoded graph summary, runtime logs).
- Manifest pointing to artifacts with OS/build and format variant.
- Notes on any harness constraints (e.g., SIP) and next steps.
