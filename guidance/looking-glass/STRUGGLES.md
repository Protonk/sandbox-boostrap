# looking-glass — STRUGGLES (working in a forbidding system)

SANDBOX_LORE is large because the real problem is large.

The *idea* of Seatbelt can fit in a blog post: SBPL compiles to a PolicyGraph; the kernel evaluates Operations through that graph; you get allow/deny. But SANDBOX_LORE is not trying to tell that story — it’s trying to **wire real claims to instruments** so we can distinguish “we saw it” from “we told a just‑so story,” and keep those claims stable as macOS and tooling shift.

That wiring is hard for structural reasons:
- The system is **confounding by default** (multiple layers can cause the same symptom; path reality diverges from string reality; “EPERM” often hides the stage that failed).
- The system is **censored by design** (many failure modes provide no specific explanation; you must create explanation by building controlled witnesses).
- The project has **many moving parts** (static artifacts, decoders, mappings, harnesses, probes, and their surrounding macOS environment).
- Agents frequently have the wrong **scope**: they try to answer a question that spans too many layers without first choosing a narrow “unit of truth.”

This bundle is a field guide to the recurring eddies that result — and the moves that reliably turn “stuck” into “bounded and decidable.”

## The four axes that cause most confusion

- **Stage**: `compile` vs `apply` (attach) vs `bootstrap` (probe start) vs `operation` checks. Many “sandbox problems” are actually stage problems.
- **Scope**: “what is the smallest claim we’re trying to make?” A good claim fits in one witness corpus or one mapping, not in a worldview.
- **Stack**: effective behavior is layered policy plus extensions plus adjacent controls; single-profile reasoning is usually incomplete.
- **Surround**: TCC, hardened runtime, SIP/platform protections, and filesystem canonicalization can impersonate sandbox behavior.

When something looks mysterious, pick one axis to interrogate first — don’t thrash across all four.

## Recurring eddies (symptoms → likely cause → next move)

- **“Everything is `EPERM` / nothing runs.”** Likely: apply-time gating or harness-identity constraints. Next move: insist on a stage label (did it attach?), then build *minimal failing* + *passing neighbor* cases.
- **“Expected deny, got allow (or vice versa), and nothing explains why.”** Likely: wrong layer (stack), wrong stage, or adjacent control. Next move: add one control that changes only the suspected confounder (e.g., switch `scenario`/`baseline` lane; test with and without a path canonicalization control; isolate a single Operation).
- **“Path rules don’t work / `/tmp` keeps betraying us.”** Likely: canonicalization or symlink/vnode resolution. Next move: design every path experiment with a canonicalization control (two spellings; one known-good baseline).
- **“Decoder says X but runtime says Y.”** Likely: you’re comparing different policy objects (recompiled vs shipped; different layer; profile didn’t attach) or the probe is doing more than you think. Next move: lock the provenance (“which exact blob/profile shape?”) and add a passing-neighbor control before interpreting the mismatch.
- **“A frozen query/index layer can’t answer something the project ‘should’ know.”** Likely: projection lag (the index is behind the tooling/artifacts). Next move: treat it as an audit signal; ask “what is the source-of-truth artifact and what would a minimal projection look like?”

## Evidence eddies (how good work becomes folklore)

- **Overclaiming from one witness**: one profile/probe “worked” and becomes a rule. Antidote: ask “what would falsify this?” and demand a second witness that varies one dimension.
- **Narrative smoothing**: inconsistent artifacts are averaged into a plausible story. Antidote: keep the inconsistency explicit (“A says allow; B says deny”), and propose the discriminating experiment.
- **Unknowns turning into semantics**: partially interpreted fields become “obvious meaning.” Antidote: keep them as bounded unknowns until they have stable witness coverage.
- **Confidence-label debates**: getting stuck on internal labels instead of operational reliance. Antidote: speak in provenance (“artifact-backed”, “runtime-witnessed”, “assumption”) and risk (“what breaks if we’re wrong?”).

## Project-structure eddies (why big repos stay big)

- **Scope creep via missing boundary objects**: without minimal failing/passing-neighbor artifacts, every future investigation restarts from scratch. Antidote: treat “boundary object creation” as a first-class deliverable.
- **Duplicate derivations**: the same fact is re-derived in multiple scripts/pipelines and silently diverges. Antidote: pick one computation as canonical and make others consumers.
- **Output sprawl**: many `out/` trees accumulate without a clear promotion/curation story. Antidote: decide what is durable, what is disposable, and what is the regeneration entrypoint.
- **Concept inventory lag**: tools evolve faster than shared vocabulary, so agents invent ad hoc terms. Antidote: force new work to name its objects in the project’s vocabulary, or explicitly label the gap.

## What to ask for when the user is stuck (no repo access)

Ask for the smallest bundle of facts that disambiguates Stage/Scope/Stack/Surround:
- **Stage**: what failed (`compile|apply|bootstrap|operation`); treat apply-adjacent `preflight` as “apply did not happen” (still not a policy decision).
- **Lane (runtime)**: `scenario|baseline|oracle` (and the channel, if relevant).
- **Intent**: which Operation(s) and what profile “shape” (filters/metafilters), in a few lines.
- **Evidence envelope (runtime)**: one repo-relative path to a committed bundle (`artifact_index.json`) or a `promotion_packet.json` (+ a small excerpt).
- **Controls**: one closest passing neighbor, and one deliberate confounder toggle (`scenario` vs `baseline`; `/tmp` vs `/private/tmp`; TCC-sensitive vs non-sensitive target).
- **Environment suspects**: any reason TCC/hardened runtime/SIP could be in play.

These questions don’t solve the sandbox — they reliably turn “forbidding” into “decidable.”
