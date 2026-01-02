# looking-glass — FRONT_LOAD (non-SYSTEM compressed starter)

This is a synthetic “front-load chunk” intended to be ingested alongside `SYSTEM.md` as a thread starter. It compresses the non-SYSTEM default pack (`MANIFEST.md`, `SANDBOX.md`, `STRUGGLES.md`, `WITNESSES.md`) and pulls in a few critical definitions from `WORLD_AND_EVIDENCE.md` where doing so reduces back-and-forth.

Baseline anchor: Sonoma 14.4.1 (23E224) Apple Silicon, SIP enabled; `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

---

## Prime directive (don’t story-tell)

When a question spans layers (SBPL ↔ compiled graphs ↔ runtime ↔ kernel ↔ environment), don’t answer by narrative. Pick the smallest **boundary object** that should decide it, then ask for the minimal excerpt/control that makes it decidable.

---

## Quick invariants (the traps that waste time)

- **Stage matters.** `compile` → `apply` (attach) → `bootstrap` (probe start) → `operation` (allow/deny decision). Apply-adjacent `preflight` means “apply did not happen” (still not a policy decision).
- **Lane matters (runtime).**
  - `scenario`: run under an applied profile (candidate for decision-stage semantics).
  - `baseline`: run without applying a profile (ambient attribution/control).
  - `oracle`: weaker side-channel lane; never implies syscall observation.
- **Apply-time failure ≠ denial.** `EPERM` at apply time is an environment gate; no PolicyGraph decision happened.
- **Path reality ≠ string reality.** `/tmp` vs `/private/tmp` and other canonicalization/symlink/vnode effects can invalidate naïve path-literal reasoning.
- **Policy is layered.** Effective behavior comes from a stack (platform policies, per-process profile, auxiliary profiles, sandbox extensions) plus adjacent systems (TCC, hardened runtime, SIP).

---

## Evidence intake (paste this first)

```text
world_id: <...>
question: <one sentence>
stage: compile|apply|bootstrap|operation (treat apply-adjacent "preflight" as apply)
lane: scenario|baseline|oracle (runtime only)
artifacts:
  - <repo-relative path to artifact_index.json OR promotion_packet.json> (+ small excerpt)
controls: <one passing neighbor> + <one confounder toggle>
```

If the output tree lacks `artifact_index.json`, treat it as debug/unverified (not evidence).

---

## Router (what to do in the first 2 minutes)

1) **Decide the stage** (is this actually a denial?).
2) **Choose the boundary object** (which witness should decide it?).
3) **Demand one control** (passing neighbor + one-variable toggle).
4) **Anchor to an envelope** (`promotion_packet.json` or committed bundle `artifact_index.json`).

---

## Declared bedrock surfaces (this host)

From `book/evidence/graph/concepts/BEDROCK_SURFACES.json`:
- Operation + Filter vocabularies:
  - `book/evidence/graph/mappings/vocab/ops.json`
  - `book/evidence/graph/mappings/vocab/filters.json`
  - `book/evidence/graph/mappings/vocab/ops_coverage.json`
- Modern format/tag-layout subset:
  - `book/evidence/graph/mappings/tag_layouts/tag_layouts.json`
- Canonical system profiles:
  - `book/evidence/graph/mappings/system_profiles/digests.json`
  - `book/evidence/graph/mappings/system_profiles/static_checks.json`
  - `book/evidence/graph/mappings/system_profiles/attestations.json`

These are “fixed inputs” for this world; everything else should point back to them or stay hypothesis.

---

## Boundary objects (pick one; ask for its excerpt/control)

Use these as “decision primitives” in design conversations.

### 1) Dyld vocab spine (Operations + Filters)
- **Decides:** what ops/filters (names+IDs) exist on this host.
- **Ask for:** ops/filters counts + 3 sample entries + dyld manifest excerpt (`book/world/<world_name>/dyld/manifest.json` or `book/evidence/graph/mappings/dyld-libs/manifest.json`).
- **Confounder:** naming ≠ behavior (vocab is structural, not semantics).

### 2) Canonical compiled-profile anchors (blobs → stable digests)
- **Decides:** what the curated system profiles look like structurally (stable identity + decoding anchors).
- **Ask for:** one excerpt from `book/evidence/graph/mappings/system_profiles/digests.json` for `sys:bsd` and `sys:airlock`.
- **Confounder:** apply-gated ≠ unrunnable-by-policy (stage confusion).

### 3) Tag layout island (bounded subset we can decode)
- **Decides:** which tags have reliable record layouts (literal/regex-bearing subset).
- **Ask for:** covered tags + record size + one exemplar decode (or excerpt from `book/evidence/graph/mappings/tag_layouts/tag_layouts.json`).
- **Confounder:** layout ≠ meaning (don’t upgrade to semantics without runtime).

### 4) Apply-gate corpus (attach-time `EPERM` ≠ denial)
- **Decides:** whether you’re blocked at apply/identity gating rather than at operation decision.
- **Ask for:** one witness row (stage+errno) + bounded log line + nearest passing neighbor.
- **Confounder:** surround (harness identity / parent environment).

### 5) VFS canonicalization suite (path literals vs runtime reality)
- **Decides:** which path spellings actually match for a path family in this world.
- **Ask for:** the suite’s “what canonicalizes, what doesn’t” summary paragraph + the tri-profile matrix result.
- **Confounder:** family/operation-specific behavior (don’t generalize `/tmp` beyond its witness).

### 6) Runtime “golden families” (narrow, but semantic)
- **Decides:** do we have repeatable decision-stage allow/deny cases for a specific op?
- **Ask for:** `promotion_packet.json` `promotability` excerpt + one `runtime_events.normalized.json` snippet for a single op.
- **Confounder:** stage/lane mixups + nested sandboxes + path normalization.

### 7) Lifecycle scaffold (PolicyWitness / App Sandbox harness)
- **Decides:** do we have an instrumented way to ask App Sandbox + entitlement questions with contract-shaped outputs?
- **Ask for:** contract fixture excerpt (help or sample observer JSON) + one committed bundle schema snippet.
- **Confounder:** surround/stack (TCC, hardened runtime, SIP can dominate).

---

## Minimal repo atlas + entrypoints (only what comes up in co-design)

Operational root: `book/`.

Most-cited evidence surfaces:
- Pinned mappings (“facts”): `book/evidence/graph/mappings/`
- Generators/promotion code: `book/graph/mappings/`
- Runtime bundles + promotion packets (evidence envelopes): produced by `book.api.runtime` and `book.api.witness`
- Frozen query layer: `book/integration/carton/`

Supported entrypoints:
- Drift detector: `make -C book test`
- Promote/refresh mappings: `python -m book.graph.mappings.run_promotion`
- Refresh CARTON: `python -m book.integration.carton.tools.update` (or `make -C book carton-refresh`)

---

## If you only remember one move

Ask for: **stage + lane + one contract-shaped artifact** + **one passing neighbor**. Everything else is interpretation, and interpretation without those anchors becomes folklore.
