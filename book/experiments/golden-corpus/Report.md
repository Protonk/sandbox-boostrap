# Golden Corpus – Report

## Purpose
Create a stable decoder regression corpus for the Sonoma baseline so structural tooling (decoder, profile_tools inspect/op-table) can be checked against a fixed set of compiled blobs. The goal is to catch drift in tag layouts, header parsing, and literal offsets without guessing semantics.

## Baseline & scope
- Host: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs: compiled SBPL blobs already in-repo (golden-triple and probe outputs). System platform blobs are out of scope until apply gates are solved.
- Tools: `book.api.profile_tools.decoder`, `book.api.profile_tools.inspect`, `book.api.profile_tools.op_table`.

## Deliverables / expected outcomes
- `out/corpus_manifest.json` – blob IDs, source paths, SHA-256, size, and category.
- `out/raw/` – header/section snapshots for each blob.
- `out/decodes/` – `decode_profile_dict` outputs per blob.
- `out/inspect/` – profile_tools inspect and op-table summaries per blob.
- `out/corpus_summary.json` – key signals (op_count, node bytes, literal start, tag histogram, layout digest) consolidated per blob.

## Plan & execution log
- Seeded experiment scaffold and outlined corpus/outputs.
- Ran `.venv/bin/python3 run.py` to collect the first corpus cut (7 blobs across golden-triple, sbpl-graph-runtime, libsandbox-encoder) and emit manifest/decodes/inspections.
- Probed platform apply gate with `book/api/SBPL-wrapper/wrapper --sbpl /System/Library/Sandbox/Profiles/airlock.sb -- /usr/bin/true`; still returns `Operation not permitted` while custom blob apply succeeds (gate still present).
- Expanded corpus with a static-only platform profile (`platform_airlock` compiled from `/System/Library/Sandbox/Profiles/airlock.sb`) and regenerated decodes/inspect snapshots.
- Added validation job `experiment:golden-corpus` under `book/graph/concepts/validation/` to replay decoder/profile_tools against the manifest; current status `ok` after normalizing tag-count comparisons.
- Refreshed `run.py` outputs after the tag-layout/contract update to bump `tag_layouts_sha256` in manifest/summary and keep decodes/inspect snapshots aligned with the current decoder.

## Evidence & artifacts
- `out/corpus_manifest.json` – blob inventory with SHA-256, size, and tag-layout digest (`08b0f5…9c965`).
- `out/corpus_summary.json` – per-blob decoder vs profile_tools signals (op_count, node bytes, literal start, tag histograms).
- `out/raw/*.json` – header/preamble/section snapshots for each blob.
- `out/decodes/*.json` – `decode_profile_dict` outputs.
- `out/inspect/*_inspect.json` and `*_op_table.json` – profile_tools summaries.
- `out/blobs/platform_airlock.sb.bin` – compiled static-only platform profile for decoder/inspect use.
- `book/graph/concepts/validation/out/experiments/golden-corpus/status.json` – validation status for rerun comparisons.

## Platform profiles (static-only)
- `platform_airlock` lives in `out/blobs/platform_airlock.sb.bin` (compiled from `/System/Library/Sandbox/Profiles/airlock.sb`).
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
