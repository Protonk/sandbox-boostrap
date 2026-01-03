# deny-delay-detail (Playbook)

This playbook captures the decision ladder used to resolve missing deny evidence on the Sonoma baseline. It is host-scoped and evidence-bounded; it is not a general claim about macOS sandbox behavior.

## Decision ladder (processual knowledge)

1) **Start with a missing deny line**
   - Symptom: probe returns `permission_error` but observer report has `observed_deny: false`.
   - Treat as provisional until observer evidence is stabilized.

2) **Switch to manual observer mode**
   - Use `sandbox-log-observer --last <window>` keyed by plan/row/correlation ID.
   - If deny lines appear reliably in manual mode, treat external range/capture as secondary.
   - Evidence: observer reports under `manual_observer/` in experiment outputs.

3) **Introduce a downloads ladder**
   - Add probes that exercise the same action via:
     - `downloads_rw` (entitlement-specific path resolution)
     - `fs_op create` (path-class downloads)
     - `fs_op create` (direct host path with `--allow-unsafe-path`)
     - `fs_coordinated_op write` (higher-level userland)
     - `sandbox_check` control (informational)
   - Use per-run unique filenames to avoid stale artifacts.
   - Treat as resolved only when deny lines appear consistently across repeated runs.

4) **Apply a stability gate**
   - Re-run the same configuration at least twice.
   - Require identical resolved rows (operation + filter) across runs before calling it stable.
   - If rows flip, treat the configuration as unstable.

5) **Escalate only if still ambiguous**
   - If manual observer mode remains unstable, consider syscall tracing (fs_usage/dtruss) last.

## What reliably resolves it (current understanding)

- Manual observer mode with the downloads ladder produces stable kernel deny lines for file-write probes across `minimal`, `net_client`, and `temporary_exception`.
- External observer mode yields lower deny evidence and more row flips.
- Capture mode is blocked by `missing child_pid for sandbox log capture`.

## Applicable situations

- Permission-shaped failures in file-write flows where deny evidence is intermittent.
- Comparisons across path-class vs direct-path semantics (containerization contrasts).
- Evaluating when observer evidence is sufficient to promote claims into shared mappings.
