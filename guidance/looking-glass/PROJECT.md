# looking-glass — PROJECT (honest appraisal)

SANDBOX_LORE is a host-bound attempt to build a **zero‑knowledge, regenerable textbook** about macOS Seatbelt: not “a story about the sandbox,” but a system where important claims are pinned to artifacts and can be re-derived by tools, so they don’t decay into folklore as macOS and profiles evolve. The project is difficult over all but the hard part is building enough instrumentation and cross-checking structure that we can say: *this claim is grounded in the host’s compiled profiles, compiler behavior, and (where possible) runtime witnesses*, and we can notice when it stops being true. We are in the middle of the hard part.

## The project arc (how we got here)

1) **Substrate + canon + example gathering**: write a disciplined vocabulary for Seatbelt and collect canonical reference material (including the 2011-era XNU sandbox lineage and later sources) to define what the project is allowed to mean by “operation,” “filter,” “policy graph,” “profile layer,” etc.

2) **Concept inventory as a contract**: formalize the insight that “knowledge” in this domain requires *multiple independent validations* (static format, compiler behavior, runtime probes, lifecycle scenarios) and that a textbook must explicitly track which concepts have which witnesses.

3) **Experiments as witness generators**: build a web of experiments that take one question at a time (vocab extraction, op-table alignment, tag layouts, apply gating, runtime probes, entitlement diffs) and emit durable artifacts rather than ephemeral conclusions.

4) **Tool + API + graph layer consolidation**: factor the successful parts into shared tooling, a validation/promotion pipeline, and reusable mappings so downstream work doesn’t keep re-deriving the same facts.

The concept inventory is not finished, but the project has real gravity: it already behaves like an instrumented research system, not a collection of notes.

## What feels solid today (strong signals)

On this host baseline, SANDBOX_LORE has a credible “static atlas” of Seatbelt:
- A host-specific **operation/filter vocabulary** derived from the system’s own binaries, treated as the naming/ID spine for everything else.
- A working picture of **compiled profile structure** (headers, op entry tables, node/tag layouts for a meaningful subset, literal/regex pools) sufficient to decode and summarize real profile blobs.
- A curated set of **canonical system profiles** that function as structural anchors: extracted, fingerprinted, decoded, and cross-checked enough to support downstream mapping work.
- An ecosystem of **guardrails and tests** whose job is to keep these structural claims from silently drifting (a “trust what’s there” signal, not just hygiene).

The tooling reflects that seriousness:
- Unified “profile byte work” utilities (compile SBPL, ingest/decode blobs, inspect, digest, op-table views).
- Runtime tooling that insists on structured, stage-aware results (`compile|apply|bootstrap|operation`), rather than letting raw stderr become the “evidence.”
- Dedicated tools for known hard problems (apply gating preflight + minimization; App Sandbox + entitlements exploration via PolicyWitness.app at `book/tools/witness/PolicyWitness.app` + `book.api.witness`).

## What is still the frontier (where the textbook is not yet zero-knowledge)

The limiting factor is not “more data,” it’s **semantic closure**: being able to tie structure → meaning → runtime behavior without hand-waving.

The biggest open gaps, in plain terms:
- **Semantic witnesses are narrow.** Runtime evidence exists, but it covers a small slice of operations and profile shapes. Many operations are known structurally but not exercised behaviorally.
- **Apply-time gates block naïve validation.** Some platform-derived profiles and some profile shapes cannot be attached from the default harness identity, which means “just run the real system profile and see” is often unavailable.
- **End-to-end lifecycle stories are incomplete.** The pipeline “entitlements + app metadata → parameterized SBPL/templates → compiled profile layers → observed decisions (plus extensions)” is the shape of the goal, but only partially realized.
- **Some low-level semantics are still under-mapped.** Where compiled node payloads and evaluator details are not yet tied to stable meanings, the project has bounded unknowns rather than a finished semantic decoder.

## What success looks like from here (the textbook endgame)

SANDBOX_LORE “wins” when a reader (or agent) can:
- Pick a concept (Operation, Filter, Metafilter, Profile Layer, Extension, Decision, lifecycle stage…),
- Follow a short chain of witnesses (static artifacts + controlled probes),
- And regenerate the same claim on the same host without trusting anyone’s memory.

Practically, that likely means:
- A small set of **golden, end-to-end case studies** (not dozens): each one demonstrates a different important mechanism and is instrumented enough to survive churn.
- A completed concept inventory where each major concept has at least one crisp witness path (and clear boundaries where we still don’t know).
- Tooling that defaults to “create boundary objects” (minimal failing + passing neighbor; stage-labeled failures; canonical controls) so progress accumulates instead of resetting.

This is the honest state: SANDBOX_LORE already has a robust structural spine and a mature instinct for guardrails; the remaining work is to manufacture a small number of semantic and lifecycle witnesses strong enough that the textbook can stop borrowing confidence from plausibility.
