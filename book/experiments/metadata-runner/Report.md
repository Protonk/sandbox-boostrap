# Metadata runner

## Purpose
- Capture a host witness for file metadata operations (stat/chmod/chown/utimes) across alias vs canonical paths, replacing the current harness gap for metadata-only ops.
- This experiment is the canonical home for **metadata canonicalization** on this world; for read/write canonicalization see `book/experiments/vfs-canonicalization/Report.md`.

## Baseline & scope
- Host baseline: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 with SIP enabled, per `book/experiments/AGENTS.md`.
- Scope: metadata-only operations and canonicalization across alias/canonical path pairs (`/tmp/*` ↔ `/private/tmp/*`, `/var/tmp/canon` ↔ `/private/var/tmp/canon`); reuses existing vocab/ops and does not cover data read/write behavior except for contrast. Metadata writes are probed via `chmod` (maps to `file-write*`), metadata reads via `lstat` (`file-read-metadata`).

## What we hope to learn
- Whether the sandbox canonicalizes metadata-only Operations (file-read-metadata, file-write-metadata) the same way it canonicalizes data read/write for `/tmp` ↔ `/private/tmp` and similar alias pairs.
- Whether metadata filters/anchors diverge from data-op behavior (e.g., denies on aliases but allows on canonical paths, or distinct errno patterns).

## How we hope to learn it
- SBPL probes isolate metadata-related Operations over the alias/canonical path pairs (allow lists for `file-read-metadata` plus `file-read*`/`file-write*`).
- Compile probes to `sb/build/*.sb.bin` for decode; apply SBPL at runtime via the Swift runner (`sandbox_init`) to avoid blob apply gates.
- Swift runner issues `lstat`/`getattrlist`/`setattrlist`/`fstat` for metadata reads and `chmod`/`utimes`/`fchmod`/`futimes`/`lchown`/`fchown`/`fchownat`/`lutimes` for metadata writes, emitting JSON with status/errno for each op/path/profile/syscall tuple.
- Driver `run_metadata.py` builds the runner, compiles SBPL, ensures fixtures under canonical paths, runs the full matrix (profiles × ops × alias/canonical), and writes `out/runtime_results.json` plus `out/decode_profiles.json`.

## How we will know it works
- Runner apply succeeds (`apply_rc=0`) against the SBPL profiles and returns deterministic allow/deny for canonical paths.
- Canonical-only and both-path profiles allow canonical path requests and record errno 0; alias-only profile denies, revealing metadata canonicalization behavior.
- Outbound artifacts (`out/runtime_results.json`, `out/decode_profiles.json`) reflect the intended path anchors and the observed allow/deny matrix without empty/parse failures.

## Deliverables / expected outcomes
- Swift-based metadata runner that issues metadata syscalls under experiment-local SBPL profiles.
- Runtime traces and decodes for metadata Operations across alias/canonical paths, paired with human-readable notes.
- Updated documentation reflecting the witness for metadata canonicalization behavior.
- Anchor-form variants (literal, subpath, regex) across alias/canonical/both profiles to determine whether anchor type affects metadata canonicalization.

## Plan & execution log
- Skeleton established with SBPL probes for alias/canonical/both path sets.
- `file-write-metadata` is not in the SBPL vocabulary; metadata writes are exercised via `file-write*` using `chmod` and `utimes`.
- Swift runner (`book/api/runtime/native/metadata_runner/metadata_runner.swift`) uses `sandbox_init` with SBPL input; driver `run_metadata.py` compiles probes, builds the runner via the shared build script, seeds fixtures, and emits runtime/decode outputs.
- Matrix coverage expanded: `file-read-metadata` via `lstat`/`getattrlist`/`setattrlist`/`fstat`; `file-write*` via `chmod`/`utimes`/`fchmod`/`futimes`/`lchown`/`fchown`/`fchownat`/`lutimes`; anchor forms tested for each profile family (literal, subpath, regex) and attrlist payload variants (`cmn`, `cmn-name`, `cmn-times`, `file-size`).
- Results: alias-only profiles deny everything; canonical-only profiles allow canonical paths and deny aliases. Anchor type matters for mixed-path profiles: literal-both still only allows canonical paths, but subpath-both and regex-both allow `/tmp/*` aliases (while `/var/tmp/canon` remains denied). `setattrlist` returns `EINVAL` on canonical paths and `EPERM` on aliases across anchor forms.

## Evidence & artifacts
- SBPL probes: `sb/metadata_*.sb`; compiled blobs: `sb/build/*.sb.bin`.
- Runner + driver: `book/api/runtime/native/metadata_runner/metadata_runner.swift`, `book/experiments/metadata-runner/run_metadata.py` (builds `book/api/runtime/native/metadata_runner/metadata_runner`).
- Outputs: `out/runtime_results.json` (matrix run) and `out/decode_profiles.json` (anchor summaries); `out/anchor_structural_check.json` (cross-check vs anchor_filter_map for available anchors).

## Blockers / risks
- No SBPL symbol for `file-write-metadata`; metadata writes are probed via `file-write*` using chmod/time/owner syscalls.
- Alias handling depends on anchor form: literal-both paths still deny alias requests, but subpath-both and regex-both allow `/tmp/*` aliases (while `/var/tmp/canon` stays denied). This diverges from data-op canonicalization (where alias + canonical literals deny alias); continue to treat anchor form as a key variable. `setattrlist` is unstable (`EINVAL` canonical, `EPERM` alias).

## Next steps
- Extend syscall coverage to include `setattrlist` (if practical) and any remaining metadata-relevant syscalls to see whether any canonicalize aliases differently.
- Add a focused allow/deny expectation matrix and guardrail tests once syscall coverage stabilizes.
- Investigate why alias requests remain denied under profiles that allow both alias and canonical literals; compare against the data-op canonicalization experiment to isolate semantic differences.
