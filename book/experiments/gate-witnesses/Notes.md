# gate-witnesses notes

- This experiment is expected to be sensitive to *where* it is run (in-harness vs “outside harness sandbox”), because a harness-level apply gate can masquerade as a profile-specific gate.
- Record runs as concrete commandlines plus pointers to `out/witnesses/.../run.json` (avoid timestamps).

- Candidate scan (outside harness sandbox): run SBPL-wrapper across `/System/Library/Sandbox/Profiles/*.sb` and collect those with apply-stage `EPERM` on this world:
  - (see output list in the shell history; current witness set uses `airlock.sb`, `blastdoor.sb`, `com.apple.CoreGraphics.CGPDFService.sb`)

- Witness generation (outside harness sandbox):
  - `python3 book/tools/preflight/preflight.py minimize-gate --input /System/Library/Sandbox/Profiles/airlock.sb --out-dir book/experiments/gate-witnesses/out/witnesses/airlock --confirm 10`
  - `python3 book/tools/preflight/preflight.py minimize-gate --input /System/Library/Sandbox/Profiles/blastdoor.sb --out-dir book/experiments/gate-witnesses/out/witnesses/blastdoor --confirm 10`
  - `python3 book/tools/preflight/preflight.py minimize-gate --input /System/Library/Sandbox/Profiles/com.apple.CoreGraphics.CGPDFService.sb --out-dir book/experiments/gate-witnesses/out/witnesses/com.apple.CoreGraphics.CGPDFService --confirm 10`

- Derived-only summaries:
  - `python3 book/experiments/gate-witnesses/summarize_features.py`

- Compile-vs-apply fork + micro-variant matrix (outside harness sandbox):
  - `python3 book/experiments/gate-witnesses/compile_vs_apply.py`

- Entitlement scan (codesign; host-local):
  - `python3 book/experiments/gate-witnesses/scan_entitlements.py`

- Message-filter xref summary (Ghidra + dyld slice string presence):
  - `python3 book/experiments/gate-witnesses/message_filter_xrefs.py`
  - To refresh the underlying Ghidra output (requires existing sandbox_kext project):
    - `PYTHONPATH=$PWD python3 book/api/ghidra/run_task.py sandbox-kext-string-refs --build 14.4.1-23E224 --project-name sandbox_kext_14.4.1-23E224 --java-home /Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home --process-existing --exec --script-args "com.apple.private.security.message-filter" "com.apple.private.security.message-filter-manager" "missing message filter entitlement" "failed to associate message filter" "cannot apply mach message filtering"`

- Apply-gate sanity check against witness controls (outside harness sandbox):
  - `book/tools/sbpl/wrapper/wrapper --preflight force --blob book/graph/concepts/validation/out/experiments/gate-witnesses/forensics/airlock/minimal_failing.sb.bin -- /bin/true`
  - `book/tools/sbpl/wrapper/wrapper --preflight force --blob book/graph/concepts/validation/out/experiments/gate-witnesses/forensics/airlock/passing_neighbor.sb.bin -- /bin/true`
  - Result: both runs now fail at `failure_stage: apply` (`sandbox_apply` EPERM); indicates a likely global-gate context rather than a profile-specific gate on this host.

- Permissive host (`--yolo`) airlock refresh:
  - `python3 book/tools/preflight/preflight.py scan /System/Library/Sandbox/Profiles/airlock.sb --jsonl`
  - `python3 book/tools/preflight/preflight.py minimize-gate --input /System/Library/Sandbox/Profiles/airlock.sb --out-dir book/experiments/gate-witnesses/out/witnesses/airlock --confirm 10`
  - Result: minimal failing still hits apply-stage `EPERM` (10/10 confirmations) while the passing neighbor is not apply-gated; preserved as `book/experiments/gate-witnesses/out/witnesses/airlock/run.yolo.json`.
  - Derived summaries: `python3 book/experiments/gate-witnesses/compile_vs_apply.py`, `python3 book/experiments/gate-witnesses/summarize_features.py`.
  - Validation refresh: `python -m book.graph.concepts.validation --experiment gate-witnesses`.

- Less permissive control pass (non-`--yolo`) airlock run:
  - `python3 book/tools/preflight/preflight.py minimize-gate --input /System/Library/Sandbox/Profiles/airlock.sb --out-dir book/experiments/gate-witnesses/out/witnesses/airlock --confirm 10`
  - Result: minimal failing still hits apply-stage `EPERM` (10/10 confirmations), but `confirm.passing_neighbor` is null (no passing neighbor confirmed); preserved as `book/experiments/gate-witnesses/out/witnesses/airlock/run.non_yolo.json`.

- Permissive host (`--yolo`) control-ok re-run:
  - `python3 book/tools/preflight/preflight.py minimize-gate --input /System/Library/Sandbox/Profiles/airlock.sb --out-dir book/experiments/gate-witnesses/out/witnesses/airlock --confirm 10`
  - Result: minimal failing still hits apply-stage `EPERM` (10/10 confirmations), passing neighbor confirmed; current `run.json` matches `run.yolo.json`.
  - Validation refresh: `python -m book.graph.concepts.validation --experiment gate-witnesses` → `status: ok`.
  - Derived summaries refreshed: `python3 book/experiments/gate-witnesses/compile_vs_apply.py`, `python3 book/experiments/gate-witnesses/summarize_features.py`.
