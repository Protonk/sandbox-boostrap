# Notes

Record probe details, commands, and observations for op coverage and runtime signature runs. Tie entries to files under `out/`.

- Ran `python book/experiments/runtime-adversarial/run_adversarial.py` (fresh runtime logs for filesystem and mach families, now including file-write* probes and a network-outbound family).
- Harvested runtime-adversarial outputs locally via `python book/experiments/op-coverage-and-runtime-signatures/harvest_runtime_artifacts.py`, so `out/` now holds the runtime/expected/mismatch JSONs this suite summarizes.
- Generated per-op summary from adversarial runtime results via `python book/experiments/op-coverage-and-runtime-signatures/summarize_from_adversarial.py` → `out/op_runtime_summary.json`. Current counts: 12 file-read* probes (10 match, 2 VFS-related mismatches), 12 file-write* probes (10 match, 2 VFS-related mismatches mirroring reads), 8 mach-lookup probes (all match), and 2 network-outbound probes (1 match for the deny profile, 1 mismatch for the allow profile even with a TCP loopback probe; stderr shows xcode-select path denial).
