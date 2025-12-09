# Plan

## Goal
Document and run probes that link per-op vocab entries to profile coverage and runtime signatures for this world.

## Tasks
- Define per-op probe profiles/SBPL snippets and inputs needed to trigger target ops.
- Decide logging/normalization format for runtime signatures and op coverage; place outputs in `out/` (keep local copies via `harvest_runtime_artifacts.py`).
- Sketch validation job intent (runtime:op-signatures) before adding code.
- Log runs and observations in `Notes.md`; summarize outcomes in `Report.md` once data exists.
