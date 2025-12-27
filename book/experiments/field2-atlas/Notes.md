# Notes — Field2 Atlas

- Initial scaffold created with seeds `0` (path), `5` (global-name), `7` (local); world fixed to `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Static/runtime/atlas outputs are currently placeholders keyed to existing mappings and golden traces; replace with regenerated data once `atlas_static.py` and `atlas_runtime.py` run.
- Keep runtime attempts, including `EPERM` / apply gates, recorded here with the command, profile, and seed field2 they target.
- Rebuilt atlas via `PYTHONPATH=. python book/experiments/field2-atlas/atlas_build.py` after refreshing `field2_inventory.json`/`unknown_nodes.json` (new UDP network variant + fcntl/right-name sweeps). Outputs remain stable (`runtime_backed` slice unchanged) but are aligned to the current anchor map/tag layouts.
- Added seed `2560` for flow-divert triple-only token (tag0/u16_role=filter_vocab_id, literal `com.apple.flow-divert`, target op `network-outbound`); regenerated static/runtime/atlas outputs to include it (static ok, runtime marked `no_runtime_candidate`).
- Refreshed static join with `PYTHONPATH=$PWD python3 book/experiments/field2-atlas/atlas_static.py`.
- Ran runtime harness refreshes: `PYTHONPATH=$PWD python3 book/experiments/runtime-checks/run_probes.py` and `PYTHONPATH=$PWD python3 book/experiments/runtime-adversarial/run_adversarial.py`.
- Regenerated runtime signatures via `PYTHONPATH=$PWD python3 book/graph/mappings/runtime/generate_runtime_signatures.py` (runtime-checks job marked `ok-changed`).
- Rebuilt runtime/atlas outputs: `PYTHONPATH=$PWD python3 book/experiments/field2-atlas/atlas_runtime.py` and `PYTHONPATH=$PWD python3 book/experiments/field2-atlas/atlas_build.py`.
- Logging-channel hypothesis check: log stream capture exists in entitlement-diff and shrink-trace outputs, but runtime_tools harness does not currently ingest log stream artifacts; treat this as a candidate measurement channel to validate separately before using it for atlas status changes.
- Added runtime-adversarial probes for path aliasing (`adv:path_alias`) and flow-divert require-all TCP (`adv:flow_divert_require_all_tcp`); ran `python3 book/experiments/runtime-adversarial/run_adversarial.py`, but all probes are apply-gated (`sandbox_init` EPERM), so seeds now record `runtime_attempted_blocked` with explicit failure_stage.
- Promoted runtime cut from runtime-adversarial (`python3 -m book.api.runtime_tools promote --staging book/experiments/runtime-adversarial/out/runtime_mappings`) and regenerated `runtime_story`, `runtime_coverage`, and `expectations`.
- `book/graph/mappings/runtime/generate_runtime_signatures.py` initially failed without `PYTHONPATH`, reran with `PYTHONPATH=$PWD` to refresh `runtime_signatures.json`.
- Rebuilt atlas runtime/summary outputs; field2=0 now carries requested/observed/normalized path observations plus a `path_canonicalization_witness` from `adv:path_alias`, and field2 1/2560 now have explicit attempted (blocked) runtime candidates.
- Added historical runtime witness carry-forward in `atlas_runtime.py` so apply-gated runs can still report last-known-good results as `runtime_backed_historical` when available.
- Decoupled observed-path collection from sandbox apply by using unsandboxed F_GETPATH; path normalization evidence now survives apply-gated runs.
- Refreshed via launchd clean channel; field2=1 mismatch now has a bounded packet in `book/experiments/runtime-adversarial/out/mismatch_packets.jsonl`, and field2=2560 carries a partial-triple control + baseline witness in `out/runtime/field2_runtime_results.json`.
- `atlas_runtime.py` now prefers the runtime-adversarial promotion packet (`out/promotion_packet.json`) for runtime_events/baseline/run_manifest paths, falling back to direct `out/` paths when absent.
