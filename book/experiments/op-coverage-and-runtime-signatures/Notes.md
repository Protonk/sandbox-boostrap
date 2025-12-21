# Notes

Record probe details, commands, and observations for op coverage and runtime signature runs. Tie entries to files under `out/`.

- Ran `python book/experiments/runtime-adversarial/run_adversarial.py` (fresh runtime logs for filesystem and mach families, now including file-write* probes and a network-outbound family).
- Harvested runtime-adversarial outputs locally via `python book/experiments/op-coverage-and-runtime-signatures/harvest_runtime_artifacts.py`, so `out/` now holds the runtime/expected/mismatch JSONs this suite summarizes.
- Generated per-op summary from adversarial runtime results via `python book/experiments/op-coverage-and-runtime-signatures/summarize_from_adversarial.py` → `out/op_runtime_summary.json`. Latest refresh ran under the permissive host context (`--yolo`) and records decision-stage outcomes again: file-read* 12 probes (10 match, 2 VFS mismatches), file-write* 12 probes (10 match, 2 VFS mismatches), mach-lookup 8/8 match, network-outbound 4/4 match.
