# looking-glass — WORLD_AND_EVIDENCE (what the repo is “about”)

This bundle captures the repo’s two binding contracts:

1) **World scoping**: every artifact and claim is scoped to a single host baseline (`world_id`).
2) **Evidence discipline**: claims are only as strong as the artifacts that back them, and runtime outcomes are only meaningful when stage/lane are explicit.

If you understand this document, you can read any other SANDBOX_LORE artifact and answer: “What world is this about?” and “What kind of evidence is this?”

Baseline anchor: Sonoma 14.4.1 (23E224) Apple Silicon, SIP enabled; `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

## 1) World model (what a `world_id` means)

A “world” is a pinned host baseline: it binds the repo’s vocab tables, mappings, decoded structures, and runtime evidence to one concrete macOS installation.

### Where worlds live

- Registry: `book/world/registry.json`
- World record: `book/world/<world_name>/world.json`
- Dyld manifest: `book/world/<world_name>/dyld/manifest.json`

World entries in the registry are typed:
- `kind: baseline` — the single baseline world the repo treats as authoritative.
- `kind: runtime` — auxiliary worlds used for runtime/dev work (not the published baseline).
- `kind: template` — intentionally null placeholders (not evidence).

### What `world.json` contains (typical fields)

`world.json` records:
- `world_id` (string) — globally identifying suffix for all host-bound artifacts.
- `host` metadata — product/version/build/kernel/machine/SIP status.
- `dyld_manifest` and optional `dyld_manifest_hash` — provenance for vocab extraction.
- `profile_format_variant`, `apply_gates`, `tcc_state` — “baseline knobs” that materially affect what the project can observe.

### How `world_id` is derived (dyld hash convention)

The repo’s convention is to derive `world_id` from the SHA256 digest of the raw dyld manifest bytes:

`<baseline>-dyld-<sha8>` where `<sha8>` is the first eight hex digits of the digest.

This is not “security”; it is a reproducibility trick: it ties the world identity to the exact dyld manifest that was used to harvest vocab and other stable tables.

### World resolution (how tools pick a world)

Most tools default to the baseline world listed in `book/world/registry.json`.

When a tool supports overrides, they are explicit (examples):
- Passing a world name/id/path to a CLI flag, or
- Passing a world reference to `book.api.world.resolve_world(...)` / `load_world(...)`.

If you see artifacts whose `metadata.world_id` differs, you are mixing worlds.

### Hypothesis-tier checkup (“doctor”)

`book/tools/doctor/` is a hypothesis-tier baseline check that verifies:
- registry lookups resolve,
- dyld manifest hash matches the world_id suffix,
- dyld libs referenced by the manifest exist and hash correctly,
- host identity signals match expectations.

It is explicitly not a mapping generator; it’s a “does this baseline look coherent?” probe.

## 2) Evidence model (how strong is a claim?)

SANDBOX_LORE uses two orthogonal label sets:

### Evidence tier (epistemic strength)

- `bedrock`
  - Declared fixed inputs for this host (for example, host vocab tables).
  - Only use when an artifact explicitly declares itself bedrock.
- `mapped`
  - Host-bound evidence-backed claims, but scoped and not universal.
  - Runtime semantics can be mapped **only** at decision-stage (`operation`) and only in scenario-scoped contexts.
- `hypothesis`
  - Partial, confounded, or unverified observations; “plausible but not promotable.”
  - Apply-stage `EPERM` is hypothesis by definition (the profile did not attach; no PolicyGraph decision happened).

### Status (operational health)

Many artifacts also carry `status: ok|partial|brittle|blocked`.

This is an operational signal (how complete/reliable the artifact is), not an upgrade/downgrade of tier.

## 3) Runtime labeling (stage + lane)

Runtime evidence must be labeled so we don’t mistake “couldn’t run” for “sandbox denied.”

### Stage (where it failed)

Use the canonical stage taxonomy:
- `compile` — SBPL -> compiled blob (structural work; not semantics).
- `apply` — profile attachment failed (no policy decision).
- `bootstrap` — apply succeeded but the probe didn’t start cleanly (still not a policy decision).
- `operation` — the probe ran an operation and observed allow/deny (this is where runtime semantics can live).

### Lane (why there are multiple records)

Lanes are distinct kinds of evidence:
- `scenario` — run under an applied profile (decision-stage semantics candidate).
- `baseline` — run without applying a profile (ambient constraints / attribution control).
- `oracle` — weaker side-channel lane; never implies syscall observation.

## 4) What “counts as evidence” in practice

When a design partner says “show me the evidence,” the strongest surfaces are:

### 4.1 Stable mappings / pinned IR

Examples:
- Vocab: `book/evidence/graph/mappings/vocab/ops.json` and `book/evidence/graph/mappings/vocab/filters.json`
- Runtime summaries: `book/evidence/graph/mappings/runtime/runtime_coverage.json`, `book/evidence/graph/mappings/runtime/runtime_signatures.json`
- Canonical profile contracts: `book/evidence/graph/mappings/system_profiles/digests.json`
- Anchors: `book/evidence/graph/mappings/anchors/anchor_field2_map.json`

These are host-bound and world-stamped (see `metadata.world_id`).

### 4.2 Committed runtime bundles (contract-shaped)

A runtime run becomes evidence only when it is a **committed bundle**:
- Bundle readiness signal: `artifact_index.json` exists.
- The bundle declares `world_id`, lists artifacts, and pins digests/sizes.

### 4.3 Promotion packets (runtime contract boundary)

Promotion packets (`promotion_packet.json`) are the contract boundary for turning runtime bundles into mappings.

They carry:
- repo-relative pointers to bundle artifacts, and
- a `promotability` block explaining whether decision-stage promotion is allowed (and why/why not).

## 5) Evidence promotion path (how knowledge becomes durable)

Most work follows one of these promotion paths:

### Static path

Source work -> normalized IR -> mappings -> CARTON

Examples:
- concepts/validation outputs under `book/evidence/graph/concepts/validation/out/`
- mapping generator outputs under `book/graph/mappings/`
- frozen query surfaces under `book/integration/carton/bundle/`

### Runtime path

plan run -> committed bundle -> promotion packet -> mappings/runtime -> CARTON

If a runtime run can’t produce a promotable packet, it remains hypothesis-tier debugging output.

## 6) The single easiest way to go wrong

Treating a “denial-shaped failure” as a sandbox denial when it is actually:
- an apply-time gate (`apply` stage),
- a probe/harness failure (`bootstrap` stage), or
- an adjacent constraint (TCC / hardened runtime / SIP / VFS canonicalization).

Stage and lane labels exist to prevent that category error.

