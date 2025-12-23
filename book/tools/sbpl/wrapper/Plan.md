# SBPL Wrapper – Plan

Goal: provide a tiny harness for applying SBPL text or compiled `.sb.bin` blobs to a process and running a command, with mechanically classifiable phase markers for the runtime contract layer.

Status (current)

- Apply surfaces:
  - `--sbpl <profile.sb> -- <cmd>…` uses `sandbox_init`.
  - `--blob <profile.sb.bin> -- <cmd>…` uses `sandbox_apply`.
  - `--compile <profile.sb> [--out <path>]` compiles only (no apply).
- Marker contract: emits JSONL `tool:"sbpl-apply"` / `tool:"sbpl-compile"` markers on stderr so runners can classify failures without substring heuristics.
- Operational preflight: `--preflight {off|enforce|force}` runs `book/tools/preflight` on the input profile before attempting apply and emits a `tool:"sbpl-preflight"` marker. In `enforce` mode, known apply-gate signatures short-circuit before apply (blocked evidence). This is an operational guardrail, not a semantic claim; see `troubles/EPERMx2.md`.

Near-term guardrails

- Keep `make -C book test` green (tests cover wrapper existence and preflight behavior).
- Keep wrapper stderr marker-free after normalization: markers must be stripped by `book/api/runtime_tools/core/contract.py`.
