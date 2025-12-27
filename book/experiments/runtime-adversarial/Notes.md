# Notes

- Re-ran `python run_adversarial.py` after adding file-write* rules to structural/path_edges SBPL and adding a network-outbound family (`net_outbound_allow`, `net_outbound_deny`).
  - Filesystem/mach families remain as before: struct_flat vs struct_nested match on read/write; path_edges shows `/tmp`→`/private/tmp` EPERM mismatches; mach literal/regex variants match.
  - Network: initial ping/TCP attempts mismatched on allow due to client startup constraints. Swapped the client to `/usr/bin/nc` (no Python in the sandbox) with explicit startup shims; TCP loopback now succeeds in allow profile and denies in deny profile.
- Refreshed `python run_adversarial.py` during the runtime_tools cutover: all adversarial probes now fail at apply (`sandbox_init` EPERM), so `out/runtime_results.json` + `out/mismatch_summary.json` reflect apply-gate blocks and the per-op summary reports only blocked counts. Treat earlier allow/deny outcomes as historical until apply succeeds again.
- Re-ran `python run_adversarial.py` after the host was made more permissive (`--yolo`): apply-stage EPERM cleared across adversarial families; only the expected `path_edges` mismatches remain and network/mach families match expectations again.
- Added `path_alias` and `flow_divert_require_all_tcp` profiles, then reran `python3 run_adversarial.py`; apply-stage EPERM persisted (`sandbox_init` failure) across all adversarial probes, so the latest outputs are blocked/partial and should be treated as attempted-only evidence.
- Added apply-only preflight capture (`out/apply_preflight.json`) with runner entitlements + parent-chain context; apply-stage EPERM is now recorded as blocked evidence separate from probe outcomes.
- Switched file-read*/file-write* probes to use `file_probe` under `sandbox_runner` so each scenario applies exactly once inside a fresh worker; added unsandboxed F_GETPATH observations to `runtime_results.json` to preserve path canonicalization evidence even when apply-gated.
- Added historical runtime event retention (`out/historical_runtime_events.json`) to keep last decision-stage witnesses when new runs are apply-gated.
- Added launchctl procinfo + libproc parent-chain attribution to `out/apply_preflight.json` and a runtime_tools clean-channel run path that requires successful apply preflight.
- Latest apply preflight shows `launchctl procinfo` requires root and `log show` is blocked (`Cannot run while sandboxed`); parent-chain attribution points at the Codex launcher path.
- Clean-channel run initially failed with `Operation not permitted` opening `run_adversarial.py` from a Desktop path; now stage the repo into `/private/tmp` via the runtime_tools clean channel and sync outputs back.
- Launchd-staged run succeeded: `out/runtime_results.json` now carries decision-stage outcomes plus sandbox_check callouts; `out/apply_preflight.json` shows `apply_ok: true`.
- Clean-channel runs now emit `out/run_manifest.json` with run_id + baseline host metadata; runtime mapping generators refuse to promote decision-stage artifacts unless `channel=launchd_clean`.
- Added unsandboxed baseline controls (`out/baseline_results.json`), a normalization control probe (`allow-subpath-normalized`), a flow-divert partial-triple profile (`flow_divert_partial_tcp`), and mismatch packets (`out/mismatch_packets.jsonl`) with enumerated mismatch reasons.
- Emitted `out/promotion_packet.json` via `python -m book.api.runtime_tools emit-promotion` for plan-based consumers (field2-atlas/runtime mapping generators).
