# codex-sandbox (Notes)

- Seeded from `book/experiments/deny-delay-detail`:
  - Source plan: `book/experiments/deny-delay-detail/codex-sandbox.md`.
  - Source notes: `book/experiments/deny-delay-detail/Notes.md`.
  - Source artifacts: `book/experiments/deny-delay-detail/out/codex-sandbox/`.
  - Artifacts copied into `book/experiments/codex-sandbox/out/codex-sandbox/` for this experiment.
  - `manifest.json` signal paths re-rooted to `book/experiments/codex-sandbox/out/codex-sandbox/`.

- Initial run (normal harness) required PYTHONPATH:
  - `python3 book/experiments/deny-delay-detail/codex_sandbox.py --mode normal` -> `ModuleNotFoundError: No module named 'book'`.
  - `PYTHONPATH=. python3 book/experiments/deny-delay-detail/codex_sandbox.py --mode normal`.

- Normal harness runs (sandboxed):
  - `PYTHONPATH=. python book/experiments/deny-delay-detail/codex_sandbox.py --mode normal` -> `42b268d9-dc59-43bd-87fc-5ee074c8a42b`.
  - `PYTHONPATH=. python book/experiments/deny-delay-detail/codex_sandbox.py --mode normal` -> `d0c480dc-8b05-4d42-9792-6f846ce196ab`.
  - `PYTHONPATH=. python3 book/experiments/deny-delay-detail/codex_sandbox.py --mode normal` -> `2f63d887-46c2-46fa-a36a-e1b46e060911`.
  - `PYTHONPATH=. python book/experiments/deny-delay-detail/codex_sandbox.py --mode normal` -> `8a0ffee3-705d-4fe8-801a-c59a254e8510`.
  - `PYTHONPATH=. python3 book/experiments/codex-sandbox/codex_sandbox.py --mode normal` -> `8992a587-9d3b-4599-853f-6983e1f26b7d`.

- Elevated harness runs (unsandboxed):
  - `PYTHONPATH=. python book/experiments/deny-delay-detail/codex_sandbox.py --mode elevated` -> `c037475a-79eb-4500-8156-813fd246c596`.
  - `PYTHONPATH=. python book/experiments/deny-delay-detail/codex_sandbox.py --mode elevated` -> `985ab309-a883-4852-bfa6-0537f8a24362`.
  - `PYTHONPATH=. python3 book/experiments/deny-delay-detail/codex_sandbox.py --mode elevated` -> `5d0e304f-db39-4130-aac2-aede2627572b`.
  - `PYTHONPATH=. python book/experiments/deny-delay-detail/codex_sandbox.py --mode elevated` -> `8c7c7dd3-5161-4116-b6c4-d01c3bc58c82`.
  - `PYTHONPATH=. python3 book/experiments/codex-sandbox/codex_sandbox.py --mode elevated` -> `27d8439e-ffb8-4fa3-9bd6-bb78fa9e5d0b`.

- For new runs, use `book/experiments/codex-sandbox/codex_sandbox.py` so outputs land under `book/experiments/codex-sandbox/out/codex-sandbox/`.
