# Preflight (profile enterability guardrail)

This tool is a **cheap, static preflight** for runtime sandbox work on the fixed SANDBOX_LORE baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).

It answers one operational question:

> “Is this profile shape known to be **apply-gated** for the harness identity on this world, such that attempts to `sandbox_init` / `sandbox_apply` will predictably fail with `EPERM` (apply-stage)?”

The intent is to stop agents and runners from learning about apply gating by repeatedly crashing into it and then narrating `EPERM` as a policy decision.

## What it does

Given either:
- SBPL source text (`.sb`)
- a compiled profile blob (`.sb.bin`)

it performs a conservative preflight and emits a JSON record per input with a classification:

- `likely_apply_gated_for_harness_identity` – a **known apply-gate signature** is present (currently: deny-style message filtering).
- `no_known_apply_gate_signature` – no known signature was found (this is **not** a guarantee that apply will succeed).
- `invalid` – SBPL parse error (preflight cannot classify).
- `unsupported` – input kind not supported by this tool.

Current signature (witness-backed on this world, but still “partial” for global scope):

- **deny-style message filtering**: any `(apply-message-filter … (deny …) …)` construct.
  - Evidence lives in the gate-witness corpus and validation outputs; see:
    - `troubles/EPERMx2.md`
    - `book/experiments/gate-witnesses/Report.md`
    - `book/graph/concepts/validation/out/experiments/gate-witnesses/witness_results.json`

Digest signature (exact-match; host-scoped list):

- `apply_gate_blob_digest` – the `.sb.bin` file’s `sha256` matches a known apply-gated blob digest from:
  - `book/graph/concepts/validation/out/experiments/preflight-blob-digests/blob_digests_ir.json`
  - `book/experiments/preflight-blob-digests/Report.md`

## Usage

From repo root:

```sh
python3 book/tools/preflight/preflight.py scan book/examples/sb/sample.sb
python3 book/tools/preflight/preflight.py scan book/experiments/gate-witnesses/out/witnesses/*/minimal_failing.sb
python3 book/tools/preflight/preflight.py scan book/graph/concepts/validation/out/experiments/gate-witnesses/forensics/*/*.sb.bin
```

Output is a JSON array by default. Use `--jsonl` for one JSON object per line.

Exit codes:

- `0` – all inputs are `no_known_apply_gate_signature`
- `2` – at least one input is `likely_apply_gated_for_harness_identity`
- `1` – at least one input is `invalid` or `unsupported`

## Notes

- This tool is intentionally **static**: it does not compile or apply profiles.
- This tool is intentionally **conservative**: it prefers “avoid dead ends” over “explain why”.
- Apply gating is “blocked” evidence for runtime semantics on this host; see `troubles/EPERMx2.md` for the repo’s phase discipline.
