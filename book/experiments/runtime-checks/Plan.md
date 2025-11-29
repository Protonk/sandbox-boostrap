# Runtime Checks (bucket-level behavior)

Goal: exercise compiled profiles at runtime to verify that observed allow/deny behavior matches the decoder’s bucket-level expectations (e.g., bucket-4 vs bucket-5 profiles). Publish traces under `book/graph/mappings/runtime/`.

---

## 1) Scope and setup

**Done**

- Identified target profiles: canonical system blobs (`airlock`, `bsd`, `sample`) and representative bucket-4/bucket-5 synthetic profiles (`v1_read`, `v11_read_subpath`) from `op-table-operation`.
- Harness in place: `run_probes.py` prefers local shims (`sandbox_runner` / `sandbox_reader`) and now uses `book/api/SBPL-wrapper/wrapper --blob` for compiled profiles.

**Upcoming**

- Record an explicit host baseline (OS/build, SIP) in `ResearchReport.md` if more runtime work resumes.
- If blob apply remains EPERM for system profiles on this host, rerun on a permissive host or adjust expectations accordingly.

Deliverables: plan/notes/report in this directory; `out/` for raw traces/logs.

## 2) Define probes and expectations

**Done**

- Listed the operations and concrete probes for bucket-4 and bucket-5 profiles (e.g., `file-read*` on `/etc/hosts` and `/tmp/foo`, `file-write*` to `/etc/hosts` / `/tmp/foo`), captured in `out/expected_matrix.json`.

**Upcoming**

- Refine expected allow/deny outcomes based on decoder bucket assignments and tag signatures once a workable runtime harness is available.

Deliverables: `out/expected_matrix.json` (profile × probe → expected verdict).

## 3) Run runtime checks

**Done (attempted)**

- Implemented `run_probes.py` to execute filesystem probes under `sandbox-exec` for the selected SBPL profiles and write results to `out/runtime_results.json`.
- Switched harness to prefer `sandbox_runner`/`sandbox_reader`; blob profiles now flow through `wrapper --blob`.

**Upcoming**

- Re-run or redesign runtime checks with a harness that can successfully apply system blob profiles on this host (current result: `sandbox_apply` → EPERM).
- Consider alternative runners or hosts if the local SIP/seatbelt policy refuses blob apply for system profiles.

**Updates**

- `sandbox_runner`/`sandbox_reader` now work on this host: bucket-4/5, allow_all, and metafilter_any complete with expected/actual/match fields (metafilter fixed by adding /private/tmp literals and reader mode).
- System profiles now run as compiled blobs through the wrapper; on this host `sandbox_apply` returns `EPERM` for those blobs, so probes record deny with apply failure noted.

Deliverables: `out/runtime_results.json` plus brief Notes.

## 4) Compare and guardrail

**Done (baseline)**

- Added a guardrail test (`tests/test_runtime_matrix_shape.py`) that asserts matrix shape and the presence of bucket-4/bucket-5 probe definitions.
- Recorded the current harness failure (`sandbox_apply: Operation not permitted`) and its implications in `ResearchReport.md` and `Notes.md`.

**Upcoming**

- Once a working harness exists, compare actual runtime results to the expected matrix and extend guardrails to cover representative allow/deny outcomes.

Stop condition: runtime traces collected for bucket-4/bucket-5 and system profiles, with a minimal guardrail and documented alignment (or gaps) with decoder expectations.

Status note: initial `sandbox-exec` attempt failed under SIP (`sandbox_apply: Operation not permitted`). Needs alternative harness or privileges.
