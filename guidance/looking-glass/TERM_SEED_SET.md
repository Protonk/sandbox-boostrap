# TERM_SEED_SET (book-only)

Only includes terms that appear somewhere under `book/` (source pointer is always a `book/...` line).

Each entry: `term` — `book/path:line` — short snippet from that line.

## World & Baseline Anchors

- `doctor` — Baseline checkup tool used to confirm host identity and report the `world_id` (it does not “fix” anything).
- `world_id` — The unique identifier for the repo’s baseline host-world; always confirm it before interpreting any evidence.
- `world.json` — The per-world record that binds host metadata and baseline knobs to a `world_id`.
- `registry.json` — The registry that resolves a world reference to its `world.json`.
- `dyld_manifest` — The dyld manifest input that anchors what userland slices and vocab are derived from for this world.
- `dyld_manifest_hash` — The digest for `dyld_manifest`, used for world identity and drift checks.
- `profile_format_variant` — A baseline knob that changes profile format/decoding assumptions for this world.
- `tcc_state` — A baseline knob capturing privacy/TCC state that can materially confound runtime observations.

## Evidence Framing

- `bedrock` — `book/AGENTS.md:10` — - Every claim must name its evidence tier: bedrock / mapped / hypothesis.
- `hypothesis` — `book/AGENTS.md:10` — - Every claim must name its evidence tier: bedrock / mapped / hypothesis.
- `mapped` — `book/profiles/golden-triple/README.md:13` — - runtime:param_deny_root_ok (parameterized SBPL witness; mapped)
- `promotability` — `book/AGENTS.md:57` — - “Why did a runtime probe fail/deny?” → book/api/runtime/ bundles and promotion packets (stage + lane + promotability).

## Sandbox Semantics & Witnessing

- `EPERM` — `book/AGENTS.md:21` — - Apply-stage EPERM is hypothesis evidence (the profile did not attach; no PolicyGraph decision happened).
- `libsandbox` — `book/examples/AGENTS.md:45` — - Demos using libsandbox extension APIs (issue / consume / release) to illustrate how (extension ...) filters act as temporary capability grants.
- `libsystem_sandbox` — `book/dumps/AGENTS.md:8` — - ghidra/private/aapl-restricted/<build>/ — extracted host artifacts (kernel KC, libsystem_sandbox, SBPL templates/compiled profiles, SYSTEM_VERSION.txt). Do…
- `PolicyGraph` — `book/profiles/golden-triple/README.md:6` — - Canonical home for golden SBPL → PolicyGraph → runtime triples on this host.
- `PolicyGraphs` — `book/graph/AGENTS.md:16` — - Python tooling that ingests/parses compiled profiles, decodes PolicyGraphs, and emits validation outputs under book/evidence/graph/concepts/validation/out/…

## SBPL & Language Layer

- `SBPL` — `book/profiles/golden-triple/CaseStudy_bucket4.md:1` — # Case study: bucket4_v1_read (SBPL → blob → graph → runtime)

## Ops / Filters (names you may say)

- `darwin-notification-post` — `book/evidence/experiments/field2-final-final/field2-atlas/Plan.md:25` — - 34 (notification-name) – present in sys:airlock tags; primary ops: darwin-notification-post/distributed-notification-post.
- `distributed-notification-post` — `book/evidence/experiments/field2-final-final/field2-atlas/Plan.md:25` — - 34 (notification-name) – present in sys:airlock tags; primary ops: darwin-notification-post/distributed-notification-post.
- `file-read*` — `book/profiles/golden-triple/CaseStudy_bucket4.md:5` — - SBPL source: book/profiles/golden-triple/bucket4_v1_read.sb ((deny default) + (allow file-read*)).
- `file-read-xattr` — `book/substrate/exegesis/APPLESANDBOXGUIDE.md:49` — * file-read-xattr – reading extended attributes; applies to vn_getxattr, vn_listxattr.
- `file-write*` — `book/chapters/chapter03-TextEdit/content/02.2-final-pack.md:158` — * The profile expects an extension to be in place before file-read*/file-write*/process-exec is allowed on those paths.
- `file-write-xattr` — `book/substrate/Appendix.md:99` — * file-read-metadata, file-write-xattr
- `iokit-open-service` — `book/evidence/experiments/archive/runtime-closure/Notes.md:68` — - Added seatbelt callouts to sandbox_iokit_probe for iokit-open-service and iokit-open-user-client (derived user-client class) gated by SANDBOX_LORE_SEATBELT…
- `mach-lookup` — `book/profiles/textedit/notes/02.4-broader-system-lessons.md:3` — - Cover common structural patterns across sandboxed apps: containerization rules, read-only system access, ubiquity/iCloud hooks, and mach-lookup allowlists…
- `network-outbound` — `book/profiles/textedit/output/02.5_code_examples.md:313` — "has_network_star": "network*" in sb_text or "network-outbound" in sb_text,
- `process-info-pidinfo` — `book/evidence/experiments/archive/hardened-runtime/Report.md:24` — - process-info-pidinfo: allow-profile attempt vs deny profile using proc_pidinfo on self and pid 1.
- `require-any` — `book/evidence/experiments/profile-pipeline/node-layout/Notes.md:58` — - Profile with (allow file-read* (require-any (subpath "/tmp/foo") (subpath "/tmp/bar"))).
- `sysctl-read` — `book/substrate/Appendix.md:119` — * sysctl-read, sysctl-write

## Graph / Mappings / Vocabulary Artifacts

- `anchor_ctx_filter_map.json` — `book/graph/AGENTS.md:43` — - Canonical (context-indexed): book/evidence/graph/mappings/anchors/anchor_ctx_filter_map.json
- `anchor_field2_map.json` — `book/graph/mappings/anchors/README.md:6` — - anchor_field2_map.json – Anchor → field2 hints derived from probe-op-structure anchor hits. Each anchor is a human-meaningful literal (path, mach name, iok…
- `anchor_filter_map.json` — `book/graph/AGENTS.md:44` — - Compatibility view (literal-keyed, conservative): book/evidence/graph/mappings/anchors/anchor_filter_map.json (guarded by book/integration/tests/graph/test…
- `attestations.json` — `book/graph/mappings/system_profiles/README.md:11` — - attestations.json + attestations/*.jsonl – Cross-linked attestations for system and golden profiles (blob sha256, op-table entries, tag counts, literal/anc…
- `concept_map.json` — `book/AGENTS.md:16` — - Use project terms from book/evidence/graph/concepts/concept_map.json and the substrate (do not invent new jargon).
- `concept_text_map.json` — `book/graph/AGENTS.md:14` — - CONCEPT_INVENTORY.md, concepts.json, concept_map.json, concept_text_map.json, EXAMPLES.md.
- `concepts.json` — `book/graph/AGENTS.md:14` — - CONCEPT_INVENTORY.md, concepts.json, concept_map.json, concept_text_map.json, EXAMPLES.md.
- `digests.json` — `book/graph/mappings/system_profiles/README.md:6` — - digests.json – Central canonical-profile mapping with per-profile status and contract:
- `filters.json` — `book/AGENTS.md:17` — - Use only ops/filters from book/evidence/graph/mappings/vocab/{ops.json,filters.json}.
- `lifecycle.json` — `book/graph/mappings/runtime/README.md:8` — - lifecycle.json + lifecycle_traces/*.jsonl — normalized lifecycle probes (entitlements, extensions) with status per scenario, host/build metadata, and sourc…
- `metadata.json` — `book/graph/mappings/op_table/README.md:12` — - metadata.json – Host/build and vocab stamps (23E224, ops=196/filters=93, status ok) plus canonical filenames for this mapping set.
- `ops.json` — `book/profiles/golden-triple/CaseStudy_bucket4.md:7` — - Operations/filters: uses vocab op file-read* (id 21 from book/evidence/graph/mappings/vocab/ops.json); no additional filters beyond the default op entrypoint.
- `ops_coverage.json` — `book/tools/inside/README.md:16` — - book/evidence/graph/mappings/vocab/ops_coverage.json
- `runtime_cuts` — `book/graph/mappings/README.md:16` — - runtime/ – Runtime mapping generators; outputs under book/evidence/graph/mappings/runtime/ and book/evidence/graph/mappings/runtime_cuts/.
- `static_checks.json` — `book/graph/mappings/system_profiles/README.md:10` — - static_checks.json – Decoder-backed invariants (header op_count, section sizes, tag_counts, tag_layout hash) for the same curated blobs; includes metadata.
- `tag_layouts.json` — `book/graph/mappings/anchors/README.md:19` — - anchor_field2_map.json is derived from book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits.json, which is produced by decoding…
- `validation_status.json` — `book/graph/concepts/validation/README.md:28` — Status schema (applies to validation_status.json and per-experiment status files):

## Runtime Bundles & Packets

- `artifact_index.json` — `book/AGENTS.md:22` — - Treat runtime results as evidence only when sourced from a committed runtime bundle (artifact_index.json) or a promotion_packet.json.
- `baseline_results.json` — `book/evidence/experiments/archive/hardened-runtime/Plan.md:19` — - out/LATEST/baseline_results.json (unsandboxed baseline comparator).
- `expected_matrix.json` — `book/api/runtime/SPEC.md:94` — - decision-stage artifacts are present (runtime_results.json, runtime_events.normalized.json, expected_matrix.json)
- `mismatch_packets.json` — `book/evidence/experiments/archive/hardened-runtime/Plan.md:21` — - out/LATEST/mismatch_packets.jsonl (bounded mismatch packets with enumerated reasons).
- `oracle_results.json` — `book/evidence/experiments/archive/hardened-runtime/Plan.md:22` — - out/LATEST/oracle_results.json (sandbox_check oracle lane only).
- `packet.json` — `book/AGENTS.md:22` — - Treat runtime results as evidence only when sourced from a committed runtime bundle (artifact_index.json) or a promotion_packet.json.
- `path_witnesses.json` — `book/api/runtime/SPEC.md:47` — ### 1.5 Path-witness IR (path_witnesses.json)
- `plan.json` — `book/AGENTS.md:44` — - Plan-based runtime run: python -m book.api.runtime run --plan <plan.json> --channel launchd_clean --out <out_dir>
- `promotion_packet.json` — `book/AGENTS.md:22` — - Treat runtime results as evidence only when sourced from a committed runtime bundle (artifact_index.json) or a promotion_packet.json.
- `promotion_receipt.json` — `book/graph/mappings/runtime/README.md:17` — - promotion_receipt.json — machine-readable receipt showing which packets were used/rejected (and why) for the current promoted cut.
- `run_manifest.json` — `book/api/README.md:66` — Role: Normalize harness output into canonical runtime observations, build runtime mappings/stories, and run plan-based probes to emit promotable runtime bund…
- `run_status.json` — `book/api/runtime/SPEC.md:20` — The bundle lifecycle is recorded in run_status.json:
- `runtime_events.normalized.json` — `book/api/runtime/SPEC.md:60` — ### 1.6 Normalized runtime events (runtime_events.normalized.json)
- `runtime_results.json` — `book/profiles/golden-triple/README.md:23` — - Runtime results (runtime_results.json) emitted by the harness against this directory.

## Tool Names

- `doctor` — `book/tools/doctor/README.md:1` — # Doctor (world baseline checkup)
- `inside` — `book/tools/inside/README.md:1` — # Inside (Codex harness sandbox detector)
- `preflight` — `book/tools/preflight/README.md:1` — # Preflight (profile enterability guardrail)
- `witness` — `book/api/witness/README.md:1` — # witness (API)
- `PolicyWitness` — `book/tools/witness/README.md:8` — PolicyWitness is a macOS research/teaching tool for exploring App Sandbox and entitlements using a host-side CLI plus sandboxed XPC services. The guide documents workflows, logging/observer behavior, and output formats.
- `PolicyWitness.app` — `book/tools/witness/README.md:3` — This directory holds PolicyWitness.app and its adjacent fixtures. It is the home for App Sandbox + entitlement tooling on the Sonoma baseline.
- `sandbox-log-observer` — `book/api/README.md:93` — Definition: Mapped-tier Python surface for PolicyWitness.app (policy-witness CLI + sandbox-log-observer).
- `XPC` — `book/tools/witness/README.md:8` — PolicyWitness is a macOS research/teaching tool for exploring App Sandbox and entitlements using a host-side CLI plus sandboxed XPC services. The guide documents workflows, logging/observer behavior, and output formats.

## API Surface Names

- `book.api.frida.cli` — `book/api/README.md:137` — python -m book.api.frida.cli run --attach-pid 12345 --script book/api/frida/hooks/smoke.js
- `book.api.ghidra` — `book/api/README.md:45` — python -m book.api.ghidra.cli --help
- `book.api.ghidra.cli` — `book/api/ghidra/README.md:13` — - Registry CLI: python -m book.api.ghidra.cli groups|list|describe (or python -m book.api.ghidra ...).
- `book.api.ghidra.refresh_canonical` — `book/api/ghidra/README.md:65` — - Refresh canonical sentinel: python -m book.api.ghidra.refresh_canonical --name <sentinel_name>
- `book.api.ghidra.scaffold` — `book/api/ghidra/README.md:14` — - CLI scaffold: python -m book.api.ghidra.scaffold <task> [--build-id ...] [--exec] ....
- `book.api.ghidra.shape_catalog_hygiene` — `book/api/ghidra/README.md:59` — - python -m book.api.ghidra.shape_catalog_hygiene – report orphan snapshots, missing fixtures,
- `book.api.ghidra.shape_manifest_prune` — `book/api/ghidra/README.md:20` — - Use python -m book.api.ghidra.shape_manifest_prune --manifest book/integration/tests/ghidra/fixtures/shape_catalog/manifest.json --report book/integration/…
- `book.api.inspect_profile` — `book/api/AGENTS.md:9` — - Legacy packages (book.api.sbpl_compile, book.api.inspect_profile, book.api.op_table) have been removed; route callers here.
- `book.api.lifecycle` — `book/api/lifecycle/README.md:38` — python -m book.api.lifecycle write-validation-out
- `book.api.op_table` — `book/api/AGENTS.md:9` — - Legacy packages (book.api.sbpl_compile, book.api.inspect_profile, book.api.op_table) have been removed; route callers here.
- `book.api.path_utils` — `book/AGENTS.md:30` — - Checked-in JSON/IR must not embed absolute paths; emit repo-relative paths using book.api.path_utils (to_repo_relative, relativize_command).
- `book.api.path_utils.to_repo_relative` — `book/api/profile/README.md:85` — - Repo-relative paths: when emitting paths in JSON, use book.api.path_utils.to_repo_relative helpers (callers and tools should not embed absolute paths in ch…
- `book.api.profile` — `book/AGENTS.md:42` — - Compile SBPL → blob: python -m book.api.profile compile <profile.sb> --out <path>
- `book.api.profile.compile` — `book/api/profile/compile/README.md:14` — - from book.api.profile.compile import compile_sbpl_file, compile_sbpl_string
- `book.api.profile.decoder` — `book/api/profile/README.md:17` — - from book.api.profile.decoder import decode_profile_dict
- `book.api.profile.digests` — `book/api/profile/README.md:30` — - book.api.profile.digests: stable, decoder-backed digests for curated blobs (notably canonical system profiles).
- `book.api.profile.identity` — `book/api/profile/README.md:31` — - book.api.profile.identity: mapping join surface for canonical system profile ids ↔ blob paths ↔ sha256 ↔ attestations.
- `book.api.profile.identity.baseline_world_id` — `book/api/frida/README.md:106` — The world baseline for tooling is resolved via book.api.profile.identity.baseline_world_id.
- `book.api.profile.ingestion` — `book/examples/sbdis/sbdis-flat.md:17` — It now uses the shared Axis 4.1 profile ingestion layer (book.api.profile.ingestion) to slice the legacy blob into header + sections, but the actual decision…
- `book.api.profile.inspect` — `book/api/profile/README.md:28` — - book.api.profile.inspect: read-only summaries for humans/guardrails (built on ingestion + decoder).
- `book.api.profile.op_table` — `book/api/profile/README.md:29` — - book.api.profile.op_table: op-table-centric summaries + SBPL token hints + vocab alignment helpers.
- `book.api.profile.oracles` — `book/api/profile/README.md:33` — - book.api.profile.oracles: structural “argument shape” extractors with byte-level witnesses (see book/api/profile/oracles/README.md).
- `book.api.profile.oracles.network` — `book/api/profile/oracles/README.md:14` — book.api.profile.oracles.network implements an extractor for the socket argument tuple using only structural witnesses established by the libsandbox-encoder…
- `book.api.profile.sbpl_scan` — `book/api/profile/sbpl_scan/README.md:15` — - from book.api.profile.sbpl_scan import parse_sbpl
- `book.api.runtime` — `book/AGENTS.md:44` — - Plan-based runtime run: python -m book.api.runtime run --plan <plan.json> --channel launchd_clean --out <out_dir>
- `book.api.sbpl_compile` — `book/api/AGENTS.md:9` — - Legacy packages (book.api.sbpl_compile, book.api.inspect_profile, book.api.op_table) have been removed; route callers here.
- `book.api.witness` — `book/api/README.md:102` — from book.api.witness import client, outputs
- `book.api.witness.client.list_profiles` — `book/api/witness/README.md:15` — - book.api.witness.client.list_profiles / list_services / show_profile / describe_service
- `book.api.witness.client.run_probe` — `book/api/witness/README.md:8` — - book.api.witness.client.run_probe / run_probe_request (one-shot probes via xpc run)
- `book.api.witness.compare.compare_action` — `book/api/witness/README.md:12` — - book.api.witness.compare.compare_action (entitlements/SBPL/none baseline comparison)
- `book.api.witness.enforcement.enforcement_detail` — `book/api/witness/README.md:11` — - book.api.witness.enforcement.enforcement_detail (minute enforcement detail from probe + observer)
- `book.api.witness.frida` — `book/api/README.md:126` — python -m book.api.witness.frida --profile-id minimal@injectable --probe-id probe_catalog --script book/api/frida/hooks/smoke.js
- `book.api.witness.lifecycle.snapshot_from_probe` — `book/api/witness/README.md:10` — - book.api.witness.lifecycle.snapshot_from_probe / snapshot_from_session (on-demand lifecycle snapshots)
- `book.api.witness.outputs.OutputSpec` — `book/api/witness/README.md:13` — - book.api.witness.outputs.OutputSpec (output layout control)
- `book.api.witness.session.open_session` — `book/api/witness/README.md:9` — - book.api.witness.session.open_session / XpcSession (xpc session control plane)
- `book.graph.mappings.run_promotion` — `book/integration/carton/README.md:42` — - python -m book.graph.mappings.run_promotion --generators runtime,system-profiles

## Surrounding Constraints / Background

- `JIT` — `book/substrate/State.md:67` — * Hardened runtime imposes constraints on how the process can behave (e.g., JIT usage, dynamic libraries, debugging) unless special entitlements are present…
- `SIP` — `book/AGENTS.md:25` — - Never weaken the baseline (no disabling SIP, TCC, or hardened runtime).
- `TCC` — `book/profiles/textedit/notes/02.4-broader-system-lessons.md:4` — - Highlight OS-wide policy surfaces visible in TextEdit’s profile (TCC/privacy services, App Store/shared content paths, logging/diagnostics endpoints).
- `VFS` — `book/AGENTS.md:74` — - Confounders: treat TCC, hardened runtime, SIP/platform gates, and VFS canonicalization as surrounding constraints that can dominate outcomes.
- `apply_gates` — `book/world/README.md:10` — - example-world/world.json — template baseline record. Populate world_id, host fields, capture reason, and runtime-impacting toggles such as profile_format_v…
- `XNU` — `book/substrate/Appendix.md:860` — * XNU’s MAC Framework (MACF) maintains per-credential security labels. Sandbox.kext stores pointers to the process’s platform and app-level profiles, as well…

## Named Artifacts / Files

- `BEDROCK_SURFACES.json` — `book/AGENTS.md:11` — - Bedrock surfaces are declared in book/evidence/graph/concepts/BEDROCK_SURFACES.json; do not upgrade mapped or hypothesis to bedrock.
- `blob.sb.bin` — `book/AGENTS.md:43` — - Decode/inspect blob: python -m book.api.profile decode dump <blob.sb.bin> --summary
- `index.json` — `book/AGENTS.md:22` — - Treat runtime results as evidence only when sourced from a committed runtime bundle (artifact_index.json) or a promotion_packet.json.
- `manifest.json` — `book/world/README.md:11` — - example-world/dyld/manifest.json — template dyld manifest (empty). For a real world, list trimmed dyld slices (paths, byte sizes, SHA256 digests) and key s…
- `profile.sb` — `book/AGENTS.md:42` — - Compile SBPL → blob: python -m book.api.profile compile <profile.sb> --out <path>
- `runtime_coverage.json` — `book/graph/mappings/runtime/README.md:24` — - runtime_signatures.json and runtime_coverage.json remain partial due to scoped mismatches (structural/path families), not due to apply gates.
- `runtime_signatures.json` — `book/profiles/golden-triple/CaseStudy_bucket4.md:13` — - Summarized in book/evidence/graph/mappings/runtime/runtime_signatures.json under signatures["bucket4:v1_read"].

## Misc

- `anchors` — `book/world/README.md:11` — - example-world/dyld/manifest.json — template dyld manifest (empty). For a real world, list trimmed dyld slices (paths, byte sizes, SHA256 digests) and key s…
- `baseline>-dyld-<sha8` — `book/world/README.md:14` — Hashing the dyld manifest is the suggested way to derive world_id. Use the raw file bytes (no reformatting) and take the first eight hex digits of the SHA256…
- `BEDROCK_SURFACES` — `book/AGENTS.md:11` — - Bedrock surfaces are declared in book/evidence/graph/concepts/BEDROCK_SURFACES.json; do not upgrade mapped or hypothesis to bedrock.
- `blocked` — `book/AGENTS.md:12` — - Many artifacts also carry status: ok|partial|brittle|blocked as an operational health/detail signal; it does not change the evidence tier.
- `brittle` — `book/AGENTS.md:12` — - Many artifacts also carry status: ok|partial|brittle|blocked as an operational health/detail signal; it does not change the evidence tier.
- `canonical system profiles` — `book/api/profile/README.md:30` — - book.api.profile.digests: stable, decoder-backed digests for curated blobs (notably canonical system profiles).
- `check` — `book/profiles/golden-triple/CaseStudy_bucket4.md:6` — - Compiled blob: book/profiles/golden-triple/bucket4_v1_read.sb.bin (also mirrored in runtime profiles under book/evidence/experiments/runtime-final-final/su…
- `complete` — `book/api/runtime/SPEC.md:23` — - state=complete – the run finished its main work and recorded a final status (the commit barrier is still artifact_index.json)
- `deny default` — `book/profiles/golden-triple/CaseStudy_bucket4.md:5` — - SBPL source: book/profiles/golden-triple/bucket4_v1_read.sb ((deny default) + (allow file-read*)).
- `diff` — `book/api/README.md:58` — python -m book.integration.carton.tools.diff
- `dyld manifest` — `book/world/README.md:3` — This directory holds per-host world baselines. Each world lives in its own subdirectory (for example sonoma-14.4.1-23E224-arm64/) with world.json plus option…
- `e.g` — `book/profiles/golden-triple/README.md:7` — - Golden criteria: simple SBPL, decoded graphs matching intent, static expectations (schema: provisional, expectation_id join key), runtime results aligned v…
- `failed` — `book/AGENTS.md:73` — - Stage taxonomy: always label where it failed (compile, apply, bootstrap, operation). Apply-stage failures are not denials.
- `failure_stage:"preflight` — `book/api/README.md:85` — - By default, the runtime harness runner runs book/tools/preflight for SBPL (.sb) and compiled SBPL blobs (.sb.bin); on a known apply-gate signature it emits…
- `field2` — `book/graph/AGENTS.md:23` — - anchors/ – anchor ↔ filter/field2 mappings.
- `fix` — `book/profiles/textedit/README.md:66` — - Parameters are fixed conceptually to application_bundle_id = "com.apple.TextEdit" and application_container_id = "com.apple.TextEdit"; paths remain paramet…
- `host` — `book/profiles/golden-triple/CaseStudy_bucket4.md:10` — - read_/etc/hosts → allow (stdout contains hosts file).
- `in_progress` — `book/api/runtime/SPEC.md:22` — - state=in_progress – the run is still writing; strict consumers must refuse to load (no stable contract)
- `launchd_clean` — `book/AGENTS.md:44` — - Plan-based runtime run: python -m book.api.runtime run --plan <plan.json> --channel launchd_clean --out <out_dir>
- `mappings` — `book/profiles/golden-triple/CaseStudy_bucket4.md:7` — - Operations/filters: uses vocab op file-read* (id 21 from book/evidence/graph/mappings/vocab/ops.json); no additional filters beyond the default op entrypoint.
- `ok` — `book/profiles/golden-triple/CaseStudy_bucket4.md:3` — Host: Sonoma 14.4.1 (23E224), CARTON bundle (manifest + relationships/views/contracts) tracked by book/integration/carton/bundle/CARTON.json.
- `partial` — `book/AGENTS.md:12` — - Many artifacts also carry status: ok|partial|brittle|blocked as an operational health/detail signal; it does not change the evidence tier.
- `promote_from_packets.py` — `book/AGENTS.md:46` — - Promote runtime packets into mappings: python book/graph/mappings/runtime/promote_from_packets.py --packets <packet.json> (writes under book/evidence/graph…
- `promotion` — `book/AGENTS.md:22` — - Treat runtime results as evidence only when sourced from a committed runtime bundle (artifact_index.json) or a promotion_packet.json.
- `SANDBOX_LORE` — `book/profiles/AGENTS.md:4` — - This tree holds host-specific profile material for SANDBOX_LORE.
- `SANDBOX_LORE_PREFLIGHT` — `book/api/README.md:87` — - Disable globally: SANDBOX_LORE_PREFLIGHT=0
- `SANDBOX_LORE_PREFLIGHT_FORCE` — `book/api/README.md:88` — - Force apply even if preflight flags a signature: SANDBOX_LORE_PREFLIGHT_FORCE=1
- `SHA256` — `book/world/README.md:11` — - example-world/dyld/manifest.json — template dyld manifest (empty). For a real world, list trimmed dyld slices (paths, byte sizes, SHA256 digests) and key s…
- `signal` — `book/AGENTS.md:12` — - Many artifacts also carry status: ok|partial|brittle|blocked as an operational health/detail signal; it does not change the evidence tier.
- `status` — `book/AGENTS.md:12` — - Many artifacts also carry status: ok|partial|brittle|blocked as an operational health/detail signal; it does not change the evidence tier.
- `status: ok|partial|brittle|blocked` — `book/AGENTS.md:12` — - Many artifacts also carry status: ok|partial|brittle|blocked as an operational health/detail signal; it does not change the evidence tier.
- `tag layouts` — `book/graph/AGENTS.md:105` — - Prefer naming and shapes that match the concept inventory (e.g., Operation Vocabulary Map, Filter Vocabulary Map, PolicyGraph, tag layouts).
- `update` — `book/AGENTS.md:34` — - CARTON fixers + manifest: python -m book.integration.carton.tools.update
- `xpc run` — `book/api/witness/README.md:8` — - book.api.witness.client.run_probe / run_probe_request (one-shot probes via xpc run)
- `xpc session` — `book/api/witness/README.md:9` — - book.api.witness.session.open_session / XpcSession (xpc session control plane)
