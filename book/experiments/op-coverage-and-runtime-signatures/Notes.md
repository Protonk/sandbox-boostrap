# Notes

- Canonical per-op runtime summary now lives at `book/graph/mappings/runtime/op_runtime_summary.json` (mapped).
- Regenerate via promotion packets and `python book/graph/mappings/runtime/promote_from_packets.py`; this suite's scripts only copy the canonical summary into `out/` and are deprecated wrappers.
- When expanding op coverage, add/adjust adversarial probe families in `book/experiments/runtime-adversarial`, then regenerate promotion packets + mappings.
