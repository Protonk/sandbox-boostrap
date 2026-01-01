# Runtime Adversarial Suite – Research Report

## Purpose
Deliberately stress static↔runtime alignment for this host using adversarial SBPL profiles. This suite covers three families:
- Structural filesystem variants (file-read*/file-write*).
- VFS edge cases (`/tmp` vs `/private/tmp`).
- Non-filesystem ops (`mach-lookup` and `network-outbound`).
Outputs: expected/runtime matrices, mismatch summaries, and impact hooks to downgrade bedrock claims if mismatches appear.

## Baseline & scope
- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (`book/world/sonoma-14.4.1-23E224-arm64/world.json`).
- Execution: `python -m book.api.runtime run --plan book/experiments/runtime-adversarial/plan.json --channel launchd_clean` (plan-based runtime CLI). Bundle outputs under `out/<run_id>/` are authoritative (resolve via `out/LATEST`). Compile/decode via `book.api.profile` and `book.api.profile.decoder`.
- Profiles: `struct_flat`, `struct_nested` (structural variants); `path_edges`, `path_edges_private`, `path_alias` (path/literal edge stress + `/tmp` alias witness + `/private/tmp` canonicalization control); `xattr` (xattr read/write discrimination over `/private/tmp` fixtures); `mach_simple_allow`, `mach_simple_variants`, `mach_local_literal`, `mach_local_regex` (mach-lookup variants); `net_outbound_allow`, `net_outbound_deny`, `flow_divert_require_all_tcp` (network-outbound variants including the flow-divert require-all triple). Custom SBPL only; no platform blobs.
- Outputs live in `sb/`, `sb/build/`, and `out/`.
- Plan/registry data is generated from the runtime template (`python -m book.api.runtime plan-build --template runtime-adversarial --out book/experiments/runtime-adversarial --overwrite`; plan-build skips expected_matrix.json by default, use `--write-expected-matrix` for a static snapshot).

## How to run
Run via the runtime CLI and treat the run-scoped bundle as the authority (`out/LATEST` points to the most recent committed run):

```sh
python -m book.api.runtime run \
  --plan book/experiments/runtime-adversarial/plan.json \
  --channel launchd_clean \
  --out book/experiments/runtime-adversarial/out
```

## Status update (launchd staged run)
- Latest refresh ran via `python -m book.api.runtime run --plan book/experiments/runtime-adversarial/plan.json --channel launchd_clean` with staging to `/private/tmp` to avoid Desktop TCC; apply preflight succeeded (`out/LATEST/apply_preflight.json` shows `apply_ok: true`).
- Clean-channel runs emit `out/LATEST/run_manifest.json` with `run_id`, baseline host metadata, staging root, and the apply preflight + sandbox_check self check; mapping generators require `channel=launchd_clean` before promoting decision-stage artifacts.
- Baseline comparator results live in `out/LATEST/baseline_results.json` (unsandboxed F_GETPATH path observations + loopback connect control for flow-divert probes) and `out/LATEST/fixtures.json` (lane-scoped loopback listener precheck markers).
- Decision-stage outcomes are present in `out/LATEST/runtime_results.json`; mismatches are restricted to the structural + path families (unexpected denies plus the known `/tmp`→`/private/tmp` normalization boundary), and the path-edge equivalence check now treats canonicalization-boundary mismatches as preserved when backed by `path_witnesses.json`.
- `out/LATEST/runtime_results.json` carries seatbelt-callout markers (sandbox_check oracle lane) for file/mach probes; treat these as additive evidence, not syscall outcomes.
- `out/LATEST/apply_preflight.json` records launchctl procinfo output, libproc parent-chain data, and the low-noise environment fingerprint; these remain attribution inputs, not sandbox semantics.
- Mismatches emit bounded `out/LATEST/mismatch_packets.jsonl` packets with baseline/oracle/normalization controls and an allowlisted `mismatch_reason` (the `adv:path_edges:allow-subpath` mismatch is labeled `canonicalization_boundary`, with a path-witness pointer).

## Families and findings

### Structural variants (struct_flat / struct_nested)
- Static intent: distinguish allowed vs denied paths under a simple subpath policy rooted at `/tmp/runtime-adv/struct/ok`.
- Runtime: unexpected denies on all allow probes for both variants (4 per profile); deny probes match expectations.
- Conclusion: structural profiles still diverge from expected allow paths; keep this bounded to the current host run and avoid promoting.

### VFS edge cases (path_edges)
- Static intent: allow literal `/tmp/runtime-adv/edges/a` and subpath `/tmp/runtime-adv/edges/okdir/*`, deny `/private/tmp/runtime-adv/edges/a` and the `..` literal to catch traversal. Decoder predicts allows on `/tmp/...` probes via literal/subpath filters.
- Runtime: `/tmp` reads are denied and flagged as `canonicalization_boundary` mismatches; writes to the same paths are unexpected denies. The normalization control (`allow-subpath-normalized`) also denies, so the mismatch packet is labeled `canonicalization_boundary` with a path-witness anchor.
- Canonicalization control: `path_edges_private` allows the normalized `/private/tmp` targets for the same `/tmp/...` probes, confirming the boundary as VFS canonicalization rather than a decoder error. The graph-shape verdicts treat this as canonicalization-aware equivalence (no counterexample) while retaining the boundary evidence. Canonicalization evidence remains anchored in `book/experiments/vfs-canonicalization/Report.md` (mapped).

### Xattr discriminators (xattr)
- Static intent: allow `file-read-xattr`/`file-write-xattr` for `/private/tmp/foo` while explicitly denying `/private/tmp/bar`. The profile is allow-default with explicit xattr denies to keep runtime prereqs clean.
- Runtime: `allow-foo-read`/`allow-foo-write` reach operation stage and allow; deny probes return the expected deny and serve as the negative control.
- Conclusion: xattr probes are decision-stage on this host and are now available as a runtime-backed witness for field2=2.

### Mach families (mach_simple_* / mach_local_*)
- Static intent: allow `mach-lookup` for `com.apple.cfprefsd.agent` only; profiles use literal vs regex and global-name vs local-name encodings, but aim for the same allow/deny surface (explicit deny on a bogus service).
- Runtime: expected allow/deny outcomes match across all mach variants in the latest run.
- Conclusion: mach runtime evidence is current and decision-stage on this host.

### Network family (net_outbound_allow / net_outbound_deny)
- Static intent: exercise `network-outbound` under deny-default profiles where the only policy difference is the presence/absence of an allow rule for outbound network.
- Runtime: decision-stage allow/deny split observed (allow profile allows, deny profile denies).
- Flow-divert control: `flow_divert_partial_tcp` is now included as a partial-triple control profile; it currently yields the same allow as the require-all profile, and that non-discriminating result is recorded explicitly.

## Evidence & artifacts
- SBPL sources: `book/experiments/runtime-adversarial/sb/*.sb`.
- Expected/runtime outputs: `book/experiments/runtime-adversarial/out/LATEST/expected_matrix.json`, `book/experiments/runtime-adversarial/out/LATEST/runtime_results.json`, `book/experiments/runtime-adversarial/out/LATEST/mismatch_summary.json`.
- Clean-channel manifest: `book/experiments/runtime-adversarial/out/LATEST/run_manifest.json` (run_id + provenance bundle).
- Baseline comparator: `book/experiments/runtime-adversarial/out/LATEST/baseline_results.json` (unsandboxed path + loopback controls).
- Fixture markers: `book/experiments/runtime-adversarial/out/LATEST/fixtures.json` (loopback listener precheck + lane-scoped fixture status).
- Mismatch packets: `book/experiments/runtime-adversarial/out/LATEST/mismatch_packets.jsonl` (decision-stage mismatches with controls + enumerated reason).
- Promotion packet: `book/experiments/runtime-adversarial/out/promotion_packet.json` (runtime promotion boundary, references bundle artifacts).
- Sandbox_check callouts: `book/experiments/runtime-adversarial/out/LATEST/runtime_results.json` includes `seatbelt_callouts` markers for file/mach probes (oracle lane only).
- Apply preflight: `book/experiments/runtime-adversarial/out/LATEST/apply_preflight.json` (runner entitlements + apply markers + parent chain).
- Bundle index: `book/experiments/runtime-adversarial/out/LATEST/artifact_index.json` (digests + schema versions).
- Fixture markers: `book/experiments/runtime-adversarial/out/LATEST/fixtures.json` (loopback listener prereq evidence).
- Mapping stub: `book/graph/mappings/runtime/adversarial_summary.json` (world-level counts).
- Guardrails: `book/integration/tests/runtime/test_runtime_adversarial.py`, `book/integration/tests/runtime/test_network_outbound_guardrail.py`, plus dyld slice manifest/checker `book/graph/mappings/dyld-libs/{manifest.json,check_manifest.py}` enforced by `book/integration/tests/graph/test_dyld_libs_manifest.py`.
- Runtime-backed ops: `book/graph/mappings/vocab/ops_coverage.json` marks `file-read*`, `file-write*`, `mach-lookup`, and `network-outbound` as having runtime evidence via runtime-checks and runtime-adversarial families; use it to decide when new probes are needed for other ops.

## Claims and limits
- Covered ops/shapes: adversarial probes cover file-read*/file-write* (bucket-4/bucket-5 filesystem profiles and structural/metafilter variants), `file-read-xattr`/`file-write-xattr` (xattr discriminators), `mach-lookup` (global-name and local-name, literal and regex, simple vs nested forms), and `network-outbound` (loopback TCP via nc under deny-default + startup shims), plus a flow-divert require-all triple profile.
- Static↔runtime alignment: decision-stage outcomes are current for mach/network families, but structural/path families still show unexpected denies; keep those mismatches scoped to this host and avoid promotion.
- Bounded mismatch: `/tmp` → `/private/tmp` canonicalization remains a known boundary from the focused VFS canonicalization experiment; it is not treated as a decoder bug.
- Scope of claims: do not treat adversarial runtime results as bedrock while apply-gated; keep `runtime_evidence` usage conservative and rely on static IR + explicit blocked status.

## Network-outbound runtime confirmation
This family targets the `network-outbound` operation to confirm mapped behavior on this host via a clean runtime allow/deny split. Early attempts that sandboxed Python hit startup/file-access noise; the final design deliberately avoids sandboxing Python and pins the client to `/usr/bin/nc`.
Current run note: decision-stage allow/deny outcomes are visible in the latest bundle outputs (apply preflight succeeded in the launchd staged run).

### Canonical scenario
- **Host**: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (this scenario is scoped to this world).
- **Client**: `/usr/bin/nc -z -w 2`.
- **Profiles**: deny default plus startup shims (`iokit-open`, `mach* sysctl-read`, `file-ioctl`, `file-read-metadata`, `file-read-data` over `/`, `/System`, `/usr`, `/Library`, `/private`, `/dev`), `system-socket`, and `process-exec` pinned to `/usr/bin/nc`.
  - `sb/net_outbound_allow.sb`: includes `allow network-outbound …`.
  - `sb/net_outbound_deny.sb`: identical except it omits `network-outbound`.
- **Topology**: two loopback targets (as emitted in `out/LATEST/expected_matrix.json`, e.g., `127.0.0.1:<port1>` and `127.0.0.1:<port2>`). The harness spins up listeners on both and runs `/usr/bin/nc` under each profile against both targets.
  - Listener setup is performed outside the sandboxed child; precheck markers are recorded in `out/LATEST/fixtures.json` so denies after a reachable precheck are treated as sandbox decisions.

### Manual control (sandbox-exec)
Before refactoring the harness, a bespoke SBPL under `sandbox-exec -f … /usr/bin/nc 127.0.0.1 <port>` with deny-default, startup shims, `system-socket`, and a localhost `network-outbound` rule showed: allow profile → successful TCP connect; deny profile → denied connect. The harness design mirrors this control, proving Sonoma + Seatbelt + `network-outbound` + `nc` works when Python is not sandboxed.

### Results and propagation
- Runtime behavior: allow profile allows both loopback probes; deny profile denies both.
- IR updates: runtime mappings and coverage have been refreshed from the latest cut; mismatches remain limited to structural/path families.

### Guardrail test
- Structural: `book/tests/planes/runtime/test_network_outbound_guardrail.py` loads `sb/net_outbound_allow.sb` and `sb/net_outbound_deny.sb` and asserts they are identical except for the `network-outbound` rule.
- Behavioral: the same test checks `adv:net_outbound_allow*` probes all yield allow and `adv:net_outbound_deny*` probes all yield deny in `out/LATEST/runtime_results.json`, and requires loopback fixture markers in `out/LATEST/fixtures.json`.
- Intent: prevents reintroducing sandboxed Python or profile shape drift that would blur the `network-outbound` decision between harness noise and PolicyGraph behavior.

### Status and adjacent work
- `network-outbound` is confirmed on this world by runtime via the canonical scenario and marked runtime-backed in coverage and CARTON.
- Planned but non-blocking: add a small variant (alternate port or IPv6 loopback) using the same client/profiles; add a “negative harness” profile (remove `system-socket`) expected to fail as a harness/startup error rather than a policy decision.
- Remaining runtime divergences: `/tmp`→`/private/tmp` VFS canonicalization in filesystem probes; see `book/experiments/vfs-canonicalization/Report.md` for the focused canonicalization family and guardrails (mapped).

## Next steps
- Extend network coverage with a small variant (alternate port or IPv6 loopback) using the same client/profiles; add a “negative harness” profile (remove `system-socket`) expected to fail as a harness/startup error rather than a policy decision.
- Keep `path_edges` behavior aligned with `book/experiments/vfs-canonicalization/Report.md` so VFS canonicalization remains explicitly modeled and bounded.
- Investigate the unexpected deny cluster in `struct_*` and `path_*` profiles before any promotion; keep sandbox_check callouts as oracle-only evidence.
- Extend families (header/format toggles, field2/tag ambiguity, additional non-filesystem ops) once current cases are stable; wire additional validation selectors if promotion to shared runtime mappings is desired.
- When running from a sandboxed parent, use the runtime clean channel (`--channel launchd_clean`) to get a clean decision-stage run.
