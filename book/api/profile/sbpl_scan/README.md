# profile.sbpl_scan

Host-scoped static SBPL scanners for the Sonoma baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).

This surface is intentionally **conservative** and **structural**:
- It parses SBPL into a minimal AST and scans for known “apply-gate” signatures.
- It does **not** evaluate policy semantics and does not guarantee runtime enterability.
- It exists to avoid dead-end runtime probes where apply-stage failures (`sandbox_apply` / `EPERM`) would otherwise be misread as decision-stage denials.

## Current surface

### Library API (stable)

Minimal parser/AST:
- `from book.api.profile.sbpl_scan import parse_sbpl`
- `from book.api.profile.sbpl_scan import Atom, ListExpr, Expr`

Scanners:
- `from book.api.profile.sbpl_scan import find_deny_message_filters`
- `from book.api.profile.sbpl_scan import classify_enterability_for_harness_identity`

Outputs:
- `find_deny_message_filters(sbpl_text) -> list[dict]` returns structural matches inside `(apply-message-filter ...)` forms.
- `classify_enterability_for_harness_identity(sbpl_text) -> dict` returns:
  - `classification`: `likely_apply_gated_for_harness_identity` or `no_known_apply_gate_signature`
  - `signature`: currently `deny_message_filter` or `None`
  - `findings`: scanner-specific records (for example the denied operation name)

## Known signature: deny-style message filtering

Current scan: any `(apply-message-filter … (deny …) …)` construct is treated as a “likely apply-gated for harness identity” signature on this world.

This is evidence-backed for this baseline but incomplete in scope; treat it as an operational guardrail, not a semantics claim. Provenance pointers:
- `troubles/EPERMx2.md`
- `book/evidence/experiments/runtime-final-final/suites/gate-witnesses/Report.md`
- `book/evidence/carton/validation/out/experiments/gate-witnesses/witness_results.json`

## Relationship to preflight

The stable operational interface is the preflight tool:
- `book/tools/preflight/preflight.py scan` wraps these scanners and adds:
  - explicit `world_id` stamping,
  - parse-error handling (`invalid`),
  - additional signatures (for example blob digest matches from validation IR).

`profile.sbpl_scan` is the library surface used by preflight and other tooling that needs the same conservative structural scan.

## Code layout

- `book/api/profile/sbpl_scan/parser.py`: tokenizer + minimal SBPL list/atom parser (not a full SBPL implementation).
- `book/api/profile/sbpl_scan/model.py`: minimal AST types.
- `book/api/profile/sbpl_scan/scan.py`: scanners and classifier functions.
