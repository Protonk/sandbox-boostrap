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

## Sandbox Semantics & Witnessing

- `EPERM` — `book/AGENTS.md:21` — - Apply-stage EPERM means the profile did not attach; no PolicyGraph decision happened.
- `sandbox_check()` — `book/tools/inside/README.md:24` —   - `sandbox_check(getpid(), NULL, 0)`.
- `libsandbox` — `book/examples/AGENTS.md:45` — - Demos using libsandbox extension APIs (issue / consume / release) to illustrate how (extension ...) filters act as temporary capability grants.

## Policy Language Primitives

- `SBPL` — `book/substrate/Concepts.md:8` — An SBPL profile is the high-level sandbox policy written in Apple’s Scheme-like sandbox DSL: it declares a version, a default decision (usually `(deny default)`), and a list of `(allow …)` / `(deny …)` rules that name operations and constrain them with filters. This is the “source code” for a Seatbelt policy that `libsandbox` parses and compiles into a binary form; it is where constructs like `file-read*`, `mach-lookup`, `subpath`, and `require-any` appear explicitly and in a way humans can read and edit.
- `deny default` — `book/substrate/Appendix.md:28` — * `(deny default)` – default decision if no rule matches (usually `deny` in built-in profiles).
- `require-any` — `book/substrate/Appendix.md:177` — Metafilters combine other filters to express Boolean structure. They are most commonly seen as `require-any`, `require-all`, and `require-not`.
- `file-read*` — `book/substrate/exegesis/APPLESANDBOXGUIDE.md:45` — * `file-read*` groups all read-like operations; its children include:
- `file-write*` — `book/substrate/exegesis/APPLESANDBOXGUIDE.md:50` — * `file-write*` groups all write-like operations; its children include:
- `mach-lookup` — `book/substrate/exegesis/APPLESANDBOXGUIDE.md:67` — * `mach-lookup` – Mach service lookup; filtered by Mach service names (e.g., `global-name "com.apple.system.logger"` or `global-name-regex`). This is how profiles whitelist specific Mach services.
- `network-outbound` — `book/substrate/exegesis/APPLESANDBOXGUIDE.md:76` — * `network-outbound` – connecting/sending; applies to `connect_nocancel`, `sendit`, `soo_write`, `unp_connect`.
- `sysctl-read` — `book/substrate/exegesis/APPLESANDBOXGUIDE.md:89` — * `sysctl*` – umbrella over sysctl read/write; and its granular forms: `sysctl-read` and `sysctl-write`. Both apply to `sysctl`, `sysctlbyname`, `sysctlnametomib`.

## Literal Handles & Context

- `anchors` — `book/graph/mappings/anchors/README.md:12` — - Anchors come from SBPL- or profile-level literals (paths, mach names, etc.) and serve as stable “handles” for specific filters in the PolicyGraph.
- `field2` — `book/graph/mappings/anchors/README.md:13` — - Together these maps connect the **literal world** (file paths, mach names) to **Filter** semantics and `field2` encodings, which is essential when reconstructing SBPL-style rules from compiled profiles or building capability catalogs around concrete resources.
- `anchor_field2_map.json` — `book/graph/mappings/anchors/README.md:6` — - `anchor_field2_map.json` – Anchor → `field2` hints derived from `probe-op-structure` anchor hits. Each anchor is a human-meaningful literal (path, mach name, iokit class) that the experiments have tied to one or more `field2` values and node indices.
- `anchor_ctx_filter_map.json` — `book/graph/mappings/anchors/README.md:7` — - `anchor_ctx_filter_map.json` – Canonical, **context-indexed** anchor→Filter bindings. This avoids treating SBPL literal strings as type-safe: the same literal can legitimately appear in multiple disjoint filter contexts (and in non-filter structural roles).
- `anchor_filter_map.json` — `book/graph/mappings/anchors/README.md:8` — - `anchor_filter_map.json` – **Derived, conservative, lossy compatibility view** keyed by literal string. It is generated from `anchor_ctx_filter_map.json` and pins a literal only when all observed contexts agree; otherwise it stays blocked and links to the underlying ctx entries via `ctx_ids`.
- `tag_layouts.json` — `book/graph/mappings/tag_layouts/README.md:6` — - `tag_layouts.json` – Best-effort per-tag layout description (record size, edge fields, payload fields) for tags that carry literal/regex operands, derived from canonical profiles on this host/build. Metadata records `status`, `canonical_profiles`, and `world_id` so tag-layout coverage stays tied to the canonical system-profile contracts.
- `tag layouts` — `book/graph/mappings/tag_layouts/README.md:10` — - The decoder (and other tools) use these layouts to interpret node fields as “follow this edge” vs “use this literal/regex operand,” which is necessary to reconstruct Filters and Metafilters from raw node bytes and to keep the PolicyGraph view consistent across experiments.

## Canonical Reference Artifacts

- `PolicyGraph` — `book/substrate/Concepts.md:199` — PolicyGraph is the compiled policy graph: the full directed graph of policy nodes and edges produced by compiling SBPL. In prose, “the policy graph” refers to an instance of this structure. For each operation, evaluation starts at the node pointed to by the operation pointer table and walks the graph until it reaches a decision node. The graph as a whole encodes the sandbox policy in a form the kernel can evaluate quickly.
- `PolicyGraphs` — `book/graph/AGENTS.md:16` — - Python tooling that ingests/parses compiled profiles, decodes PolicyGraphs, and emits validation outputs under book/evidence/graph/concepts/validation/out/…
- `CARTON` — `book/integration/carton/README.md:3` — CARTON is the integration-time contract for SANDBOX_LORE: a small, reviewable bundle that freezes host-bound facts, their provenance, and the invariants we refuse to drift on. The primary interface is **fix + verify + explain drift**.
- `CARTON.json` — `book/integration/carton/README.md:7` — - `bundle/CARTON.json` — generated manifest (schema v2) with digest, role, size, and world binding.
- `bundle/relationships/` — `book/integration/carton/README.md:8` — - `bundle/relationships/` — canonical relationship outputs (operation coverage, profile-layer ops, anchor field2, etc.).
- `bundle/views/` — `book/integration/carton/README.md:9` — - `bundle/views/` — derived indices built from relationships (operation_index, profile_layer_index, filter_index, concept_index, anchor_index).
- `bundle/contracts/` — `book/integration/carton/README.md:10` — - `bundle/contracts/` — derived claim snapshots (review surface).
- `concepts.json` — `book/graph/README.md:7` — - Emits JSON: `book/evidence/graph/concepts/{concepts.json,concept_map.json,concept_text_map.json}`, `book/evidence/graph/concepts/validation/{strategies.json,validation_report.json}`, `book/examples/examples.json`.
- `concept_map.json` — `book/graph/README.md:7` — - Emits JSON: `book/evidence/graph/concepts/{concepts.json,concept_map.json,concept_text_map.json}`, `book/evidence/graph/concepts/validation/{strategies.json,validation_report.json}`, `book/examples/examples.json`.
- `concept_text_map.json` — `book/graph/README.md:7` — - Emits JSON: `book/evidence/graph/concepts/{concepts.json,concept_map.json,concept_text_map.json}`, `book/evidence/graph/concepts/validation/{strategies.json,validation_report.json}`, `book/examples/examples.json`.
- `ops.json` — `book/graph/mappings/vocab/README.md:8` — - `ops.json` / `filters.json` – Primary Operation/Filter vocab maps (ID ↔ name plus provenance). These are the authoritative operation/filter ID tables for this host/build.
- `filters.json` — `book/graph/mappings/vocab/README.md:8` — - `ops.json` / `filters.json` – Primary Operation/Filter vocab maps (ID ↔ name plus provenance). These are the authoritative operation/filter ID tables for this host/build.
- `ops_coverage.json` — `book/graph/mappings/runtime/README.md:30` — - Use `book/evidence/graph/mappings/vocab/ops_coverage.json` and explicit status fields to gauge what is currently runtime-backed vs blocked on this host.
- `digests.json` — `book/graph/mappings/system_profiles/README.md:6` — - `digests.json` – Central canonical-profile mapping with per-profile status and contract:
- `canonical system profiles` — `book/api/profile/README.md:30` — - book.api.profile.digests: stable, decoder-backed digests for curated blobs (notably canonical system profiles).
- `static_checks.json` — `book/graph/mappings/system_profiles/README.md:10` — - `static_checks.json` – Decoder-backed invariants (header op_count, section sizes, tag_counts, tag_layout hash) for the same curated blobs; includes `metadata`.
- `attestations.json` — `book/graph/mappings/system_profiles/README.md:11` — - `attestations.json` + `attestations/*.jsonl` – Cross-linked attestations for system and golden profiles (blob sha256, op-table entries, tag counts, literal/anchor hits, tag-layout hash, vocab versions, runtime links when available); includes `metadata`.
- `metadata.json` — `book/graph/mappings/op_table/README.md:12` — - `metadata.json` – Host/build and vocab stamps (23E224, ops=196/filters=93, status ok) plus canonical filenames for this mapping set.
- `lifecycle.json` — `book/graph/mappings/runtime/README.md:8` — - `lifecycle.json` + `lifecycle_traces/*.jsonl` — normalized lifecycle probes (entitlements, extensions) with status per scenario, host/build metadata, and source log pointers.
- `runtime_cuts` — `book/graph/mappings/README.md:16` — - `runtime/` – Runtime mapping generators; outputs under `book/evidence/graph/mappings/runtime/` and `book/evidence/graph/mappings/runtime_cuts/`.
- `validation_status.json` — `book/graph/concepts/validation/README.md:28` — Status schema (applies to `validation_status.json` and per-experiment status files):

## Runtime Bundles & Packets

- `artifact_index.json` — `book/AGENTS.md:22` — - Treat runtime results as evidence only when sourced from a committed runtime bundle (artifact_index.json) or a promotion_packet.json.
- `expected_matrix.json` — `book/api/runtime/SPEC.md:94` — - decision-stage artifacts are present (runtime_results.json, runtime_events.normalized.json, expected_matrix.json)
- `plan.json` — `book/AGENTS.md:44` — - Plan-based runtime run: python -m book.api.runtime run --plan <plan.json> --channel launchd_clean --out <out_dir>
- `promotion_packet.json` — `book/AGENTS.md:22` — - Treat runtime results as evidence only when sourced from a committed runtime bundle (artifact_index.json) or a promotion_packet.json.
- `promotion_receipt.json` — `book/graph/mappings/runtime/README.md:17` — - promotion_receipt.json — machine-readable receipt showing which packets were used/rejected (and why) for the current promoted cut.
- `run_manifest.json` — `book/api/README.md:66` — Role: Normalize harness output into canonical runtime observations, build runtime mappings/stories, and run plan-based probes to emit promotable runtime bund…
- `runtime_events.normalized.json` — `book/api/runtime/SPEC.md:60` — ### 1.6 Normalized runtime events (runtime_events.normalized.json)
- `runtime_results.json` — `book/profiles/golden-triple/README.md:23` — - Runtime results (runtime_results.json) emitted by the harness against this directory.

## Tool Names

- `doctor` — `book/tools/doctor/README.md:1` — # Doctor (world baseline checkup)
- `inside` — `book/tools/inside/README.md:1` — # Inside (Codex harness sandbox detector)
- `preflight` — `book/tools/preflight/README.md:1` — # Preflight (profile enterability guardrail)
- `sbpl` — `book/tools/sbpl/README.md:1` — # SBPL tools
- `witness` — `book/api/witness/README.md:1` — # witness (API)
- `PolicyWitness` — `book/tools/witness/README.md:8` — PolicyWitness is a macOS research/teaching tool for exploring App Sandbox and entitlements using a host-side CLI plus sandboxed XPC services. The guide documents workflows, logging/observer behavior, and output formats.
- `PolicyWitness.app` — `book/tools/witness/README.md:3` — This directory holds PolicyWitness.app and its adjacent fixtures. It is the home for App Sandbox + entitlement tooling on the Sonoma baseline.
- `policy-witness` — `book/api/witness/README.md:30` — - `policy-witness xpc run --profile ...` -> `client.run_probe`
- `sandbox-log-observer` — `book/api/witness/README.md:36` — - `sandbox-log-observer` -> `observer.run_sandbox_log_observer`
- `XPC` — `book/tools/witness/README.md:8` — PolicyWitness is a macOS research/teaching tool for exploring App Sandbox and entitlements using a host-side CLI plus sandboxed XPC services. The guide documents workflows, logging/observer behavior, and output formats.

## API Surface Names

- `book.api.profile` — `book/api/README.md:7` — Definition: Unified surface for SBPL compilation, compiled-blob decoding/inspection, op-table summaries, and structural oracles (replaces `sbpl_compile`, `inspect_profile`, `op_table`, and the former standalone `decoder`/`sbpl_oracle` modules).
- `book.api.runtime` — `book/api/README.md:64` — Definition: Unified runtime tooling (observations, mappings, projections, plan-based execution, and harness runner/golden generator).
- `book.api.witness` — `book/api/README.md:95` — Role: Run probes across profiles, capture observer deny evidence, compare baselines, and expose lifecycle/enforcement detail without binding tooling to experiment paths.
- `book.api.world` — `book/api/world.py:2` — World registry resolver helpers.
- `book.api.path_utils` — `book/api/path_utils.py:2` — Helpers for consistent repo-root path handling.

## Surrounding Constraints / Background

- `JIT` — `book/substrate/State.md:67` — * Hardened runtime imposes constraints on how the process can behave (e.g., JIT usage, dynamic libraries, debugging) unless special entitlements are present…
- `SIP` — `book/AGENTS.md:25` — - Never weaken the baseline (no disabling SIP, TCC, or hardened runtime).
- `TCC` — `book/profiles/textedit/notes/02.4-broader-system-lessons.md:4` — - Highlight OS-wide policy surfaces visible in TextEdit’s profile (TCC/privacy services, App Store/shared content paths, logging/diagnostics endpoints).
- `VFS` — `book/AGENTS.md:74` — - Confounders: treat TCC, hardened runtime, SIP/platform gates, and VFS canonicalization as surrounding constraints that can dominate outcomes.
- `apply_gates` — `book/world/README.md:10` — - example-world/world.json — template baseline record. Populate world_id, host fields, capture reason, and runtime-impacting toggles such as profile_format_v…
- `XNU` — `book/substrate/Appendix.md:860` — * XNU’s MAC Framework (MACF) maintains per-credential security labels. Sandbox.kext stores pointers to the process’s platform and app-level profiles, as well…
