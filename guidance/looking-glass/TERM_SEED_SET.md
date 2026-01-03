# TERM_SEED_SET (book-only)

## World & Baseline Anchors
This section is the minimum vocabulary for anchoring any co-design conversation to the repo’s single host baseline: confirm the `world_id` (often via `doctor`) before interpreting anything, then use the world files and baseline knobs here as the compact explanation of “what world are we in?” and “what can confound runtime observations on this host?”.

- `doctor`
- `world_id`
- `world.json`
- `registry.json`
- `dyld_manifest`
- `dyld_manifest_hash`
- `profile_format_variant`
- `tcc_state`
Just right: it centers `doctor`/`world_id` and keeps the world binding + key knobs small enough to prevent “world spelunking”.

## Sandbox Semantics & Witnessing
This section holds the small set of semantics you can safely say out loud in a short chat without accidentally overstating what a run proved; `EPERM` is included because it is commonly the tell that something failed before a policy decision was even in play.

- `EPERM`
Too small: the section currently captures only the most common apply-gate symptom and omits other everyday “what does this outcome mean?” shorthands.

## Policy Language Primitives
These are the names you’ll see in SBPL text and in sandbox rule discussions: a default posture (`deny default`), a representative metafilter (`require-any`), a few high-signal operation families, and the filter keys that most often show up when you describe what a rule is “about” (path, Mach service name, notification name, xattr).

- `SBPL`
- `libsandbox`
- `deny default`
- `require-any`
- `file-read*`
- `file-write*`
- `mach-lookup`
- `network-outbound`
- `sysctl-read`
- `path`
- `global-name`
- `notification-name`
- `xattr`
Just right: it gives enough shared language to talk about policy shape without turning this into an exhaustive op/filter catalog.

## Literal Handles & Context
This section is about how the project bridges human-readable literals (paths, Mach names, attribute names) into stable handles and internal encodings; when you see “anchor”, “field2”, or “tag layout”, it’s usually pointing at these mapping artifacts rather than at a single profile or one-off run.

- `anchors`
- `field2`
- `anchor_field2_map.json`
- `anchor_ctx_filter_map.json`
- `anchor_filter_map.json`
- `tag_layouts.json`
- `tag layouts`
Just right: it names the core “literal → internal handle” surfaces without forcing co-designers to learn the full mapping pipeline.

## Canonical Reference Artifacts
This section names the repo’s “authoritative cut” surfaces: the PolicyGraph vocabulary layer, the pinned system-profile identities, and the generated bundles/contracts that CARTON and the guardrail suite treat as stable references for the current world (and as the place you look when something “drifts”).

- `PolicyGraph`
- `PolicyGraphs`
- `guardrail`
- `guardrails`
- `drift`
- `CARTON`
- `CARTON.json`
- `bundle/relationships/`
- `bundle/views/`
- `bundle/contracts/`
- `canonical system profiles`
- `sys:airlock`
- `sys:bsd`
- `sys:sample`
- `concepts.json`
- `concept_map.json`
- `concept_text_map.json`
- `ops.json`
- `filters.json`
- `ops_coverage.json`
- `digests.json`
- `static_checks.json`
- `attestations.json`
- `metadata.json`
- `lifecycle.json`
- `runtime_cuts`
- `runtime_signatures.json`
- `runtime_coverage.json`
- `validation_status.json`
Too big: it’s a useful grab-bag for pointing at “the canonical artifacts”, but it mixes high-level nouns with many specific filenames that a short co-design chat may never need.

## Runtime Bundles & Packets
These terms describe how runtime work is structured and serialized: a run’s classification (`stage`/`lane`), its execution channel (`launchd_clean`), and the bundle/packet files that record outcomes and support promotion into the repo’s mappings.

- `stage`
- `lane`
- `compile|apply|bootstrap|operation`
- `scenario|baseline|oracle`
- `launchd_clean`
- `artifact_index.json`
- `expected_matrix.json`
- `plan.json`
- `promotion_packet.json`
- `promotion_receipt.json`
- `run_manifest.json`
- `runtime_events.normalized.json`
- `runtime_results.json`
Just right: it captures the taxonomy + the handful of runtime artifacts that are repeatedly referenced in reviews and comparisons.

## Tool Names
These are the names of the host-facing tools and components you’ll reference in conversation: detecting whether you are already sandboxed (`inside`/`sandbox_check()`), deciding whether a profile can be applied (`preflight`), working with SBPL/profile blobs (`sbpl`), and using the PolicyWitness stack to probe/observe decisions via an app + XPC services + observer tooling.

- `inside`
- `sandbox_check()`
- `preflight`
- `sbpl`
- `witness`
- `PolicyWitness`
- `PolicyWitness.app`
- `policy-witness`
- `sandbox-log-observer`
- `XPC`
Just right: it’s the smallest set of tool names that come up repeatedly without forcing you into operational details.

## API Surface Names
These are the stable Python module surfaces the repo treats as “the API”: profile compilation/inspection, runtime plan execution and normalization, witness/probing, world resolution, and consistent repo-relative path handling.

- `book.api.profile`
- `book.api.runtime`
- `book.api.witness`
- `book.api.world`
- `book.api.path_utils`
Just right: it’s intentionally short and points at the five interfaces that tend to matter in short co-design threads.

## Surrounding Constraints / Background
These are the ambient macOS/system constraints that often dominate outcomes or interpretation (independent of “the policy”): hardened-runtime/JIT constraints, SIP/TCC, filesystem canonicalization effects, apply-time gating, and the underlying XNU/MAC substrate that Seatbelt plugs into.

- `JIT`
- `SIP`
- `TCC`
- `VFS`
- `apply_gates`
- `XNU`
Just right: it’s a compact reminder of the most common confounders without expanding into general macOS background.
