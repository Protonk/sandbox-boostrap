# looking-glass — FRONT_LOAD (human-speed co-design glossary + mental model)

This file is a **single-chunk context bundle** for short co-design conversations about **SANDBOX_LORE**.

Purpose:
- Let a co-designer hear and use SANDBOX_LORE shorthand (e.g., `inside`, `doctor`, `CARTON`) **without confusion**.
- Front-load the project’s **mental model** and **evidence posture** so co-design stays grounded.
- Reduce “where do I look?” thrash by naming the few **canonical surfaces** where truth lives.

Non-goals:
- This is not an operational runbook and does not try to teach command-line workflows.
- This file assumes the co-designer does **not** have repository access; when repo-grounded detail is needed, the right move is to ask the user to paste a small excerpt from a pinned artifact.

Baseline anchor (scope for all claims here): Sonoma 14.4.1 (23E224) Apple Silicon, SIP enabled; `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

Only supported repo-wide test entrypoint (the only command we name here): `make -C book test`.

---

## 0) How to use this in a short co-design chat

If you only have 3 minutes:
1) Confirm you’re talking about the baseline world (`world_id` above).
2) Use the glossary (Section 3) so terms like `CARTON`, `inside`, `doctor`, and `promotion_packet.json` land correctly.
3) When a claim is contentious, anchor it to an evidence surface (Section 2). If you can’t, treat it as hypothesis or generic lore.

If you have 10 minutes:
4) Use the “confusion breakers” (Section 1) to avoid category errors: stage ≠ denial, lane ≠ syscall tracing, path strings ≠ path reality.
5) Use the “talk tracks” (Section 4) to speak in SANDBOX_LORE’s native framing without accidentally promising more certainty than the artifacts support.

---

## 1) Confusion breakers (the few invariants that prevent folklore)

### 1.1 World scoping is the binding contract

SANDBOX_LORE is host-bound: every durable artifact is scoped to **one world** (one baseline machine + OS build). If the `world_id` differs, you are mixing worlds. Mixed-world discussion is almost always wasted effort.

### 1.2 Stage matters (denial-shaped ≠ denial)

Many “sandbox problems” are not sandbox decisions. SANDBOX_LORE insists on a stage taxonomy so we don’t turn a failure-shaped symptom into a deny story:
- `compile`: SBPL → compiled blob (structural; not semantics)
- `apply`: profile attach failed (no PolicyGraph decision happened)
- `bootstrap`: profile attached but probe didn’t start cleanly (still not a PolicyGraph decision)
- `operation`: the probe ran and observed allow/deny at decision time (this is where semantics can live)

Apply-adjacent `preflight`:
- Some tooling reports an apply-avoidance guardrail as `preflight`. Treat it as “apply did not happen” (still not a policy decision).

### 1.3 Lane matters (runtime evidence attribution)

Runtime evidence is recorded in “lanes” that answer different questions:
- `scenario`: run under an applied profile (candidate for decision-stage semantics)
- `baseline`: run without applying a profile (ambient constraints control)
- `oracle`: weaker side-channel lane; never implies syscall observation

Common category error:
- People treat `oracle` as “kernel saw a deny.” Don’t. It is an attribution hint lane, not syscall tracing.

### 1.4 Path reality ≠ string reality

VFS canonicalization and vnode resolution can make a path rule behave differently than naïve string matching suggests. A classic alias family is `/tmp` ↔ `/private/tmp`.

Design implication:
- Any co-design that depends on path literals should explicitly acknowledge canonicalization risk unless it’s backed by a canonicalization witness.

### 1.5 Policy is layered; adjacent systems impersonate sandbox behavior

Effective outcomes come from a stack:
- platform policies + per-process profile + auxiliary profiles,
- sandbox extensions (dynamic grants),
- and adjacent controls that can produce denial-shaped outcomes:
  - TCC (privacy database/prompting),
  - hardened runtime constraints,
  - SIP / platform protections,
  - VFS canonicalization,
  - nested sandboxes or unexpected profile stacking.

---

## 2) Where truth lives (the canonical surfaces)

Think of SANDBOX_LORE as a set of “contract surfaces.” In co-design, you can move fast by pointing to the right surface instead of retelling a story.

### 2.1 Pinned mappings (“facts” you can build on)

Pinned mapping outputs live under:
- `book/evidence/graph/mappings/`

These are world-stamped, reviewable JSON artifacts that other tooling and CARTON are allowed to depend on.

Important split:
- **Pinned outputs**: `book/evidence/graph/mappings/**`
- **Generator code** (writes pinned outputs): `book/graph/mappings/**`

If someone confuses the two, they will talk as if code is evidence or as if evidence is editable by hand.

### 2.2 Runtime evidence envelopes (what makes “we ran it” promotable)

Runtime work becomes durable only when it is captured in contract-shaped envelopes:
- a committed run directory with `artifact_index.json` (commit barrier),
- and often a `promotion_packet.json` (contract boundary explaining promotability).

Without the commit barrier, treat results as debugging output (still useful, but not evidence-grade).

### 2.3 CARTON (frozen query bundle)

CARTON is the integration-time contract: a small, reviewable bundle that freezes host-bound facts + provenance + invariants we refuse to drift on.

Home:
- `book/integration/carton/`

Key idea for co-design:
- CARTON is a **projection**. If CARTON can’t answer something the repo “should” know, the usual issue is projection lag. Ask for the underlying pinned mapping/bundle and propose the smallest projection needed.

### 2.4 Worlds (baseline records)

World registry + world records live under:
- `book/world/`

World records bind artifacts to a single baseline and carry provenance like dyld manifests.

### 2.5 Substrate + concept inventory (what terms are allowed to mean)

SANDBOX_LORE tries to prevent “vibes-based taxonomy” by treating vocabulary as part of the project’s contract. Concepts and term maps exist so co-design doesn’t invent incompatible jargon.

Home:
- `book/substrate/` (definitions + framing)
- `book/evidence/graph/concepts/` (concept inventory + generated concept maps)

---

## 2.6 Declared bedrock surfaces (this host)

Bedrock is “declared fixed input” for this world. The project explicitly declares bedrock surfaces in:
- `book/evidence/graph/concepts/BEDROCK_SURFACES.json`

Declared bedrock mapping paths for this baseline:

Operation + Filter vocabularies:
- `book/evidence/graph/mappings/vocab/ops.json`
- `book/evidence/graph/mappings/vocab/filters.json`
- `book/evidence/graph/mappings/vocab/ops_coverage.json`

Modern format/tag-layout subset:
- `book/evidence/graph/mappings/tag_layouts/tag_layouts.json`

Canonical system profiles:
- `book/evidence/graph/mappings/system_profiles/digests.json`
- `book/evidence/graph/mappings/system_profiles/static_checks.json`
- `book/evidence/graph/mappings/system_profiles/attestations.json`

Everything else is either:
- `mapped` (artifact-backed but bounded), or
- `hypothesis` (confounded, partial, or not contract-shaped).

---

## 3) Glossary of shorthand tokens (meaning + common wrong interpretation)

This is the main value of this bundle: a fast glossary so short conversations don’t derail.

Format:
- **Means:** what the token refers to in SANDBOX_LORE.
- **Avoid:** the common wrong interpretation to guard against.
- **Where:** the canonical home surface (path) to ground discussion.

### 3.1 World + baseline tokens

**`world`**
- Means: a pinned host baseline that scopes vocab, mappings, and runtime evidence to one concrete macOS installation.
- Avoid: “a conceptual environment” or “a VM.” It’s a specific build/hardware baseline.
- Where: `book/world/`

**`world_id`**
- Means: the world’s globally identifying string; used as a binding suffix/prefix for durable artifacts.
- Avoid: “a version label you can ignore.” A mismatch means you’re mixing worlds.
- Where: `book/world/<world_name>/world.json`

**`baseline world`**
- Means: the single authoritative world the repo treats as “the one we claim about.”
- Avoid: “just the default choice; other worlds are equivalent.”
- Where: `book/world/registry.json`

**`world.json`**
- Means: the baseline record (host identity, world_id, baseline knobs, dyld manifest provenance).
- Avoid: “a config file.” It’s a contract record.
- Where: `book/world/<world_name>/world.json`

**`registry.json`**
- Means: the index used to resolve the baseline world.
- Avoid: “a cache.” It’s part of baseline binding.
- Where: `book/world/registry.json`

**`dyld manifest`**
- Means: provenance for dyld cache slices used to harvest stable vocab/tables.
- Avoid: “just a list of libraries.” It’s part of world identity and reproducibility.
- Where: `book/world/<world_name>/dyld/manifest.json`

### 3.2 Evidence posture tokens

**`bedrock`**
- Means: declared fixed input for this world. Only use when explicitly declared.
- Avoid: “anything we feel confident about.”
- Where: `book/evidence/graph/concepts/BEDROCK_SURFACES.json`

**`mapped`**
- Means: artifact-backed claim strong within a bounded scope (often scenario-scoped decision-stage runtime evidence, or stable mapping outputs).
- Avoid: “universal semantics” or “bedrock-lite.”
- Where: usually `book/evidence/graph/mappings/**` (and promoted runtime summaries)

**`hypothesis`**
- Means: partial/confounded/unverified observations; plausible but not promotable.
- Avoid: “wrong.” Hypothesis is often the correct label for early signals and apply-stage failures.
- Where: often experiment outputs; also `doctor` outputs are explicitly hypothesis-tier.

**`status: ok|partial|brittle|blocked`**
- Means: operational health/detail signal.
- Avoid: treating it as evidence tier. Status does not upgrade epistemic strength.
- Where: appears on many artifacts and reports; tier rules live in concept docs.

### 3.3 Runtime language tokens

**`stage`**
- Means: where a run failed or succeeded (`compile|apply|bootstrap|operation`).
- Avoid: “just a label.” It decides whether allow/deny claims are even meaningful.
- Where: runtime bundle artifacts and promotion packets.

**`lane`**
- Means: why there are multiple records (`scenario|baseline|oracle`).
- Avoid: treating `oracle` as tracing; treating `baseline` as “no sandbox at all.”
- Where: runtime bundle artifacts.

**`artifact_index.json`**
- Means: the commit barrier for a runtime output directory; pins artifacts + digests/sizes.
- Avoid: “an optional index.” If it’s missing, don’t treat the run as evidence-shaped.
- Where: inside a committed runtime bundle directory.

**`promotion_packet.json`**
- Means: the contract boundary between runtime bundles and pinned runtime mappings; carries pointers and a `promotability` decision.
- Avoid: “the evidence itself.” It’s a decision record about promotion and provenance.
- Where: emitted from a committed runtime bundle (and later used to generate pinned runtime mappings).

**`promotability`**
- Means: the packet’s explanation of whether decision-stage promotion is allowed (and why).
- Avoid: “a subjective opinion.” It is a contract boundary to prevent folklore.
- Where: `promotion_packet.json`

**`run_manifest.json`**
- Means: run identity + world binding + channel + metadata (what was run and under what assumptions).
- Avoid: “just metadata.” It’s how you prevent world mixing.
- Where: committed runtime bundle directory.

**`expected_matrix.json`**
- Means: what the run intended to test (expectations, controls).
- Avoid: treating it as “ground truth.” It’s the plan’s intent, not necessarily what happened.
- Where: committed runtime bundle directory.

**`runtime_events.normalized.json`**
- Means: normalized per-event evidence with confounder hints; often the smallest deciding excerpt for a single op.
- Avoid: treating it as raw syscall trace.
- Where: committed runtime bundle directory.

**`path_witnesses.json`**
- Means: FD-reported path spellings to keep VFS canonicalization visible without ad hoc parsing.
- Avoid: assuming paths are stable strings (see canonicalization confounder).
- Where: committed runtime bundle directory (when present).

### 3.4 Static mapping tokens

**`mappings`**
- Means: pinned, world-stamped JSON “facts” under `book/evidence/graph/mappings/`.
- Avoid: “generated output you can hand-edit.” It’s a contract layer.
- Where: `book/evidence/graph/mappings/`

**`promotion`**
- Means: the deliberate act of turning raw/validation/runtime outputs into pinned mappings and then into CARTON projections.
- Avoid: “just rerunning scripts.” Promotion is meant to be reviewable and bounded.
- Where: conceptually spans validation IR → mappings → CARTON.

**`ops / filters vocab`**
- Means: the host-specific Operation/Filter names+IDs that everything keys off.
- Avoid: assuming they are stable across macOS versions or across worlds.
- Where: `book/evidence/graph/mappings/vocab/ops.json` and `book/evidence/graph/mappings/vocab/filters.json`

**`tag layouts`**
- Means: stable record layouts for a bounded subset of tags in the modern compiled format.
- Avoid: assuming “we can decode everything” or that layout implies semantics.
- Where: `book/evidence/graph/mappings/tag_layouts/tag_layouts.json`

**`canonical system profiles` / `sys:bsd` / `sys:airlock`**
- Means: curated compiled profile blobs treated as structural anchors with stable digests/contracts.
- Avoid: assuming they are always apply-able or that apply failures imply denies.
- Where: `book/evidence/graph/mappings/system_profiles/digests.json`

**`anchors`**
- Means: mapping files that tie decoded structural slots to stable meanings in bounded contexts.
- Avoid: treating them as universal semantics; they are scope-limited closures.
- Where: `book/evidence/graph/mappings/anchors/`

**`field2`**
- Means: a u16 payload slot in certain compiled node records; sometimes partially interpreted depending on tag/context.
- Avoid: guessing its meaning from a few examples; keep bounded unknowns explicit.
- Where: often referenced via anchor maps and tag role inventories.

**`runtime_cuts`**
- Means: a promoted, query-friendly slice of runtime evidence (indexes/traces/scenario docs) derived from promotable packets.
- Avoid: treating it as raw tracing; it’s a projection for analysis and indexing.
- Where: `book/evidence/graph/mappings/runtime_cuts/`

### 3.5 Integration/guardrail tokens

**`CARTON`**
- Means: integration-time contract bundle: frozen facts + provenance + invariants + query-friendly indices.
- Avoid: treating CARTON as “the only source of truth.” It’s a stable projection; underlying mappings still matter.
- Where: `book/integration/carton/` (manifest: `book/integration/carton/bundle/CARTON.json`)

**`relationships` / `views` / `contracts` (CARTON sub-bundles)**
- Means:
  - relationships: canonical relationship outputs
  - views: derived indices built from relationships
  - contracts: human review snapshots derived from relationships
- Avoid: treating contracts as primary evidence (they are derived).
- Where: `book/integration/carton/bundle/relationships/`, `.../views/`, `.../contracts/`

**`drift`**
- Means: a detected mismatch between pinned invariants/contracts and regenerated outputs.
- Avoid: treating drift as “tests are annoying.” Drift is a signal that a claim may have decayed.
- Where: surfaced via CARTON checks/diffs and integration tests.

**`guardrails`**
- Means: tests and invariants that make drift loud (not “unit tests for macOS”).
- Avoid: thinking they validate the OS; they validate repo wiring + contracts.
- Where: `book/integration/` (and CARTON tooling/spec)

### 3.6 Tool/harness tokens (the ones you’ll casually reference)

**`doctor`**
- Means: a hypothesis-tier baseline checkup tool that verifies world/dyld integrity and compares host identity signals; it does not update mappings or CARTON.
- Avoid: “doctor fixes the repo” or “doctor is bedrock.” It’s explicitly hypothesis-tier.
- Where: `book/tools/doctor/` (outputs typically under `book/tools/doctor/out/<world_id>/`)

**`inside`**
- Means: a harness sandbox detector: determines whether the current process is already sandbox-constrained so policy-facing runs don’t misread harness gates as policy decisions.
- Avoid: “inside tells me whether the sandbox denied X.” It’s about harness confinement, not op semantics.
- Where: `book/tools/inside/` (see `book/tools/inside/README.md`)

**`preflight`**
- Means: apply-gate avoidance/guardrail tooling (static scan + dynamic minimization) that prevents repeated crashes into apply gating from becoming deny folklore.
- Avoid: “preflight proves apply will succeed.” It’s conservative and partial by design.
- Where: `book/tools/preflight/`

**`PolicyWitness`**
- Means: a sandboxed app + host-side tooling for App Sandbox/entitlements questions using XPC services and contract-shaped outputs.
- Avoid: “PolicyWitness is a syscall tracer” or “observer output is tracing.” It’s a harness with attribution surfaces.
- Where: `book/tools/witness/PolicyWitness.app` and `book/tools/witness/fixtures/contract/`

**`sandbox-log-observer`**
- Means: a deny attribution observer that reads sandbox log signals outside the sandboxed process.
- Avoid: treating it as kernel tracing; it’s attribution evidence, not syscall observation.
- Where: referenced in PolicyWitness fixtures under `book/tools/witness/fixtures/contract/`

---

## 4) Talk tracks (how to speak SANDBOX_LORE without accidental overclaiming)

Use these patterns to keep co-design precise and fast.

### 4.1 When you cite a claim, bind it to world + surface

Good:
- “On `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`, the ops/filters vocab is bedrock, pinned under `book/evidence/graph/mappings/vocab/`.”
- “That runtime outcome is only design-grade if it’s decision-stage (`stage: operation`) and comes with a promotability decision.”

Bad:
- “macOS sandbox does X” (unscoped; invites generic lore and version mixing).
- “it failed with EPERM so the sandbox denied it” (stage confusion).

### 4.2 When you say “CARTON,” also say “projection”

Fast clarifier:
- “CARTON is the frozen query bundle; it’s a projection of underlying mappings and promoted runtime evidence. If CARTON can’t answer, we go to the mapping/bundle and decide whether to extend the projection.”

### 4.3 When you say “doctor,” also say “hypothesis-tier checkup”

Fast clarifier:
- “Doctor checks baseline coherence (world/dyld/host signals). It doesn’t update mappings and it doesn’t prove semantics.”

### 4.4 When you say “inside,” also say “harness confinement detector”

Fast clarifier:
- “Inside tells you whether the *harness environment* is already sandbox-constrained, which would confound policy-facing runs.”

### 4.5 When you talk about denies, make stage explicit

Fast clarifier:
- “Is this `apply`/`bootstrap`/`operation`? Only `operation` is a policy decision.”

### 4.6 When you talk about paths, say “canonicalization risk”

Fast clarifier:
- “Be careful with `/tmp`; path spelling and kernel path reality can differ.”

---

## 5) Minimal “what to paste” prompts (non-operational)

If you need to ground a discussion without giving a full repo tour, ask the user to paste:
- The `world_id` line (or the `world.json` snippet that shows it).
- One small excerpt from a pinned mapping JSON (if discussing vocab/tag layouts/system profile anchors).
- Or, for runtime: a small excerpt from `promotion_packet.json` (especially `promotability`) plus confirmation that `artifact_index.json` exists in the run directory.

Keep excerpts short (the goal is disambiguation, not transcript).

---

## 6) One supported drift detector

If something seems inconsistent, the project’s single supported repo-wide drift detector is:
- `make -C book test`

Co-design meaning:
- This isn’t “unit tests for macOS.” It is the repo’s alarm system for contract drift: world mixing, schema drift, path normalization regressions, broken projections, and broken tooling contracts.

If `make -C book test` fails, that failure is evidence about repo health; it’s not something to hide or narrate away.
