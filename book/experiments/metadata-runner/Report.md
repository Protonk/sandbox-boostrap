# Metadata runner

## Purpose
- Capture a host witness for file metadata operations (stat/chmod/chown/utimes) across alias vs canonical paths, replacing the current harness gap for metadata-only ops.

## Baseline & scope
- Host baseline: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 with SIP enabled, per `book/experiments/AGENTS.md`.
- Scope: metadata-only operations and canonicalization across alias/canonical path pairs; reuses existing vocab/ops and does not cover data read/write behavior except for contrast.

## What we hope to learn
- Whether the sandbox canonicalizes metadata-only Operations (file-read-metadata, file-write-metadata) the same way it canonicalizes data read/write for `/tmp` ↔ `/private/tmp` and similar alias pairs.
- Whether metadata filters/anchors diverge from data-op behavior (e.g., denies on aliases but allows on canonical paths, or distinct errno patterns).

## How we hope to learn it
- TODO: document the probe design and runner flow once implemented.

## How we will know it works
- TODO: add success criteria once the runner is defined (expected allow/deny matrix, error codes, and decoder alignment).

## Deliverables / expected outcomes
- Swift-based metadata runner that issues metadata syscalls under experiment-local SBPL profiles.
- Runtime traces and decodes for metadata Operations across alias/canonical paths, paired with human-readable notes.
- Updated documentation reflecting the witness for metadata canonicalization behavior.

## Plan & execution log
- Skeleton created; runner design and probes are pending.

## Evidence & artifacts
- `out/` – reserved for runtime outputs and decoder artifacts once probes exist.

## Blockers / risks
- Metadata runner not built yet; may need bridging code to align syscall results with existing validation tooling.

## Next steps
- Design the metadata syscall coverage and integrate the runner into the experiment workflow.
