# Plan

## Goal
Keep a per-operation runtime summary aligned with promotable runtime packets for this world.

## Tasks
- Run runtime-checks and runtime-adversarial via runtime (launchd_clean) and emit promotion packets.
- Regenerate canonical runtime mappings with `book/graph/mappings/runtime/promote_from_packets.py` (includes `op_runtime_summary.json`).
- Expand adversarial probe families when new ops need runtime coverage; document new families and results in `Report.md`/`Notes.md`.
