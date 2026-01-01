# Plan

## Goal
Probe semantically equivalent profile variants with differing graph shapes/tags to see whether runtime behavior matches intent.

## Tasks
- Draft profile pairs/families with clear plain-language intent (allow/deny scenarios) and structural differences (nesting/order/sharing/tag tweaks).
- Define fixed probe scenarios (paths/syscalls/inputs) and normalization format for decoded graphs + runtime outcomes into derived outputs under `out/derived/<run_id>/`.
- Outline validation job intent (graph-shape-equivalence) to compare structure vs behavior before adding code.
- Log concrete probes in `Notes.md`; summarize results in `Report.md` after runs.
