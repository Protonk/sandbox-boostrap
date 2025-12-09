# Metadata runner

## Purpose
- Capture a host witness for file metadata operations (stat/chmod/chown/utimes) across alias vs canonical paths, replacing the current harness gap for metadata-only ops.

## Baseline & scope
- Host baseline: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 with SIP enabled, per `book/experiments/AGENTS.md`.
- Scope: metadata-only operations and canonicalization across alias/canonical path pairs (`/tmp/*` ↔ `/private/tmp/*`, `/var/tmp/canon` ↔ `/private/var/tmp/canon`); reuses existing vocab/ops and does not cover data read/write behavior except for contrast. Metadata writes are probed via `chmod` (maps to `file-write*`), metadata reads via `lstat` (`file-read-metadata`).

## What we hope to learn
- Whether the sandbox canonicalizes metadata-only Operations (file-read-metadata, file-write-metadata) the same way it canonicalizes data read/write for `/tmp` ↔ `/private/tmp` and similar alias pairs.
- Whether metadata filters/anchors diverge from data-op behavior (e.g., denies on aliases but allows on canonical paths, or distinct errno patterns).

## How we hope to learn it
- SBPL probes isolate metadata-related Operations over the alias/canonical path pairs (allow lists for `file-read-metadata` plus `file-read*`/`file-write*`).
- Compile probes to `sb/build/*.sb.bin` for decode; apply SBPL at runtime via the Swift runner (`sandbox_init`) to avoid blob apply gates.
- Swift runner issues `lstat` for metadata reads and `chmod` for metadata writes, emitting JSON with status/errno for each op/path/profile tuple.
- Driver `run_metadata.py` builds the runner, compiles SBPL, ensures fixtures under canonical paths, runs the full matrix (profiles × ops × alias/canonical), and writes `out/runtime_results.json` plus `out/decode_profiles.json`.

## How we will know it works
- Runner apply succeeds (`apply_rc=0`) against the SBPL profiles and returns deterministic allow/deny for canonical paths.
- Canonical-only and both-path profiles allow canonical path requests and record errno 0; alias-only profile denies, revealing metadata canonicalization behavior.
- Outbound artifacts (`out/runtime_results.json`, `out/decode_profiles.json`) reflect the intended path anchors and the observed allow/deny matrix without empty/parse failures.

## Deliverables / expected outcomes
- Swift-based metadata runner that issues metadata syscalls under experiment-local SBPL profiles.
- Runtime traces and decodes for metadata Operations across alias/canonical paths, paired with human-readable notes.
- Updated documentation reflecting the witness for metadata canonicalization behavior.

## Plan & execution log
- Skeleton established with SBPL probes for alias/canonical/both path sets.
- `file-write-metadata` is not in the SBPL vocabulary; metadata writes are exercised via `file-write*` using `chmod`.
- Swift runner built (`metadata_runner.swift`) using `sandbox_init` with SBPL input; driver `run_metadata.py` compiles probes, builds the runner, seeds fixtures, and emits runtime/decode outputs.
- First matrix run shows: canonical-only and both-path profiles allow canonical requests (read-metadata + chmod) and deny alias requests; alias-only profile denies all, suggesting metadata probes do not inherit the alias canonicalization observed for data read/write.

## Evidence & artifacts
- SBPL probes: `sb/metadata_*.sb`; compiled blobs: `sb/build/*.sb.bin`.
- Runner + driver: `metadata_runner.swift`, `run_metadata.py` (builds runner to `build/metadata_runner`, ignored in git).
- Outputs: `out/runtime_results.json` (matrix run) and `out/decode_profiles.json` (anchor summaries).

## Blockers / risks
- No SBPL symbol for `file-write-metadata`; chmod-based `file-write*` is a proxy for metadata writes.
- Alias requests are denied even when alias literals are present (and when canonical literals are present in the both-path profile), diverging from the data-op canonicalization story; needs follow-up probes to confirm whether this is inherent to metadata ops or to syscall choice (lstat/chmod).

## Next steps
- Extend syscall coverage (e.g., `getattrlist`, `utimes`, `chown`) to see whether different metadata syscalls map to distinct Operations or canonicalization paths.
- Add a focused allow/deny expectation matrix and guardrail tests once syscall coverage stabilizes.
- Investigate why alias requests remain denied under profiles that allow both alias and canonical literals; compare against the data-op canonicalization experiment to isolate semantic differences.
