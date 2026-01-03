# Golden Corpus – Report

> Archived experiment scaffold. Canonical corpus + builders live under `book/evidence/graph/concepts/validation/golden_corpus/` (`*_build.py`, `*_job.py`).

## Purpose
Create a stable decoder regression corpus for the Sonoma baseline so structural tooling (decoder, `book.api.profile` inspect/op-table) can be checked against a fixed set of compiled blobs. The goal is to catch drift in tag layouts, header parsing, and literal offsets without guessing semantics.

## Baseline & scope
- Host: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs: compiled SBPL blobs already in-repo (golden-triple and probe outputs), plus a static-only platform fixture (`platform_airlock`).
- Tools: `book.api.profile.decoder`, `book.api.profile.inspect`, `book.api.profile.op_table`.

## Deliverables / expected outcomes
- `book/evidence/graph/concepts/validation/golden_corpus/corpus_manifest.json` – blob IDs, source paths, SHA-256, size, and category.
- `book/evidence/graph/concepts/validation/golden_corpus/raw/` – header/section snapshots for each blob.
- `book/evidence/graph/concepts/validation/golden_corpus/decodes/` – `decode_profile_dict` outputs per blob.
- `book/evidence/graph/concepts/validation/golden_corpus/inspect/` – `book.api.profile` inspect and op-table summaries per blob.
- `book/evidence/graph/concepts/validation/golden_corpus/corpus_summary.json` – key signals (op_count, node bytes, literal start, tag histogram, layout digest) consolidated per blob.

## Plan & execution log
- Seeded experiment scaffold and outlined corpus/outputs.
- Ran the canonical builder `book/evidence/graph/concepts/validation/golden_corpus_build.py` to collect the first corpus cut (7 blobs across golden-triple, sbpl-graph-runtime, libsandbox-encoder) and emit manifest/decodes/inspections.
- Probed platform apply gate with `book/tools/sbpl/wrapper/wrapper --sbpl /System/Library/Sandbox/Profiles/airlock.sb -- /usr/bin/true`; still returns `Operation not permitted` while custom blob apply succeeds (gate still present).
- Expanded corpus with a static-only platform profile (`platform_airlock` via the fixture blob compiled from `/System/Library/Sandbox/Profiles/airlock.sb`) and regenerated decodes/inspect snapshots.
- Added validation job `experiment:golden-corpus` under `book/integration/carton/validation/` to replay decoder/profile against the manifest; current status `ok` after normalizing tag-count comparisons.
- Canonical builder now lives at `book/evidence/graph/concepts/validation/golden_corpus_build.py`; the experiment-local wrapper was deleted on archival.

## Evidence & artifacts
- `book/evidence/graph/concepts/validation/golden_corpus/corpus_manifest.json` – blob inventory with SHA-256, size, and `tag_layouts_sha256`.
- `book/evidence/graph/concepts/validation/golden_corpus/corpus_summary.json` – per-blob decoder vs profile signals (op_count, node bytes, literal start, tag histograms).
- `book/evidence/graph/concepts/validation/golden_corpus/raw/*.json` – header/preamble/section snapshots for each blob.
- `book/evidence/graph/concepts/validation/golden_corpus/decodes/*.json` – `decode_profile_dict` outputs.
- `book/evidence/graph/concepts/validation/golden_corpus/inspect/*_inspect.json` and `*_op_table.json` – profile summaries.
- `book/evidence/graph/concepts/validation/fixtures/blobs/airlock.sb.bin` – static-only platform profile fixture for decoder/inspect use.
- `book/evidence/graph/concepts/validation/out/experiments/golden-corpus/status.json` – validation status for rerun comparisons.

## Platform profiles (static-only)
- `platform_airlock` uses the fixture blob `book/evidence/graph/concepts/validation/fixtures/blobs/airlock.sb.bin` (compiled from `/System/Library/Sandbox/Profiles/airlock.sb`).
- Platform/system profiles in this experiment are **decoder-only artifacts**: compiled and decoded for structural regression (op-table layout, tag histograms, literals), never applied at runtime.
- Rationale: apply is gated by platform policy (`sandbox_init`/`sandbox_apply` returns `EPERM` for these profiles on this host), and SANDBOX_LORE treats platform/system profiles as static structure only in this world.

## Blockers / risks
- System platform blobs remain apply-gated on this host: attempts to apply compiled platform profiles (e.g., `sys:airlock`, `sys:bsd`) return `EPERM`/blocked in the SBPL-wrapper/runtime harness. This is an environment constraint, not evidence the profiles are fake, and it limits us to static decoding rather than runtime runs for those profiles.
- Decoder remains heuristic; guardrails will flag drift but not prove semantic correctness.

## Next steps
- Status/coverage: golden corpus currently includes seven runtime-capable custom blobs plus `platform_airlock` as a static-only platform profile.
- Any future ability to run platform profiles at runtime would require a new experiment and likely a status change, not a silent extension of this one.
- Keep validation job in the smoke loop; consider promoting more platform/system profiles as static-only entries.
- Expand corpus with additional platform/system profiles once decoded, maintaining the static-only stance and noting any apply-gate observations.
