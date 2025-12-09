# Notes

Record probe details, commands, and observations for op coverage and runtime signature runs. Tie entries to files under `out/`.

- Ran `python book/experiments/runtime-adversarial/run_adversarial.py` (fresh runtime logs for filesystem and mach families, now including file-write* probes and a new network-outbound family).
- Generated per-op summary from adversarial runtime results via `python book/experiments/op-coverage-and-runtime-signatures/summarize_from_adversarial.py` → `out/op_runtime_summary.json`. Shows 12 file-read* probes (10 match, 2 VFS-related mismatches), 12 file-write* probes (10 match, 2 VFS-related mismatches mirroring reads), 8 mach-lookup probes (all match), and 2 network-outbound probes (1 match for the deny profile, 1 mismatch for the allow profile due to ping exiting with errno -6).
