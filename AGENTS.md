# Agents start here

This repo defines a fixed, opinionated “world” for the macOS Seatbelt sandbox and expects agents to stay inside it. All reasoning and code should be grounded in this world, not in generic or cross-version macOS lore.

Use this file as the root-level contract for agents. The root `README.md` gives a human-facing overview; directory-specific norms and workflows always live in the nearest `AGENTS.md` inside each subtree.

If you stay within this world—substrate definitions, host-specific artifacts, and the existing concept inventory—your changes and explanations will fit cleanly into SANDBOX_LORE’s model of the macOS sandbox. When in doubt about local norms or workflows, stop and read the closest `AGENTS.md` and README in the subtree you are about to change. 

## The most important rule

When the simplest honest answer is “we don’t know yet” or “current evidence is inconsistent,” say that explicitly and point to the experiments or mappings that bound that ignorance.

## Validation tiers

Every claim belongs to a tier: **bedrock** (call it bedrock and cite the mapping path; see `book/graph/concepts/BEDROCK_SURFACES.json` for the current set), **mapped-but-partial** (label it “partial”, “brittle”, or “under exploration” in text/comments), or **substrate-only** (state that there is no host witness yet and this is a substrate hypothesis). If you quote a claim that sounds global (“the sandbox does X”), also say which tier it is in; do not silently upgrade partial/brittle or substrate-only statements to bedrock.

## World and scope

- The world is a single host baseline:
  - macOS Sonoma 14.4.1 (23E224), Apple Silicon, SIP enabled.
- All architectural and behavioral claims are about this host unless explicitly labeled otherwise.
- A pre-set understanding of the world is committed to, provisionally, in `substrate/`. Read `substrate/Canon.md` to understand its warp and weft.

## Substrate and vocabulary discipline

- Treat `substrate/` as the normative theory of Seatbelt for this host:
  - `Orientation.md` – lifecycle/story and high-level architecture.
  - `Concepts.md` – exact definitions (Operation, Filter, PolicyGraph, Profile Layer, etc.).
  - `Appendix.md` – SBPL, compiled formats, node structure, entitlements.
  - `Environment.md` – containers, neighboring systems (TCC, hardened runtime, SIP).
  - `State.md` – how the sandbox shows up on macOS 13–14 in practice.
  - `Canon.md` - how the substrate was constructed and is bounded.
- Answer questions and draft text using the project’s own vocabulary, not generic OS-security jargon. When you need a concept choose existing names from `substrate/Concepts.md`

## Evidence model and mappings

- Static artifacts on this host are primary:
  - Compiled profiles, dyld cache extracts, decoded PolicyGraphs, vocab tables, and mapping JSONs under `book/graph/mappings/`.
- Experiments under `book/experiments/` and validation tooling under `book/graph/concepts/validation/` are the bridge between substrate theory and artifacts; promotion to `book/graph/mappings/` should go through these tools, not direct JSON edits.
- Validation status is part of the meaning:
  - Treat `status: ok` / `partial` / `brittle` / `blocked` as semantic qualifiers; do not silently upgrade partial or blocked evidence to fact.
- Operation and Filter vocabularies:
  - Use only names and IDs defined in `book/graph/mappings/vocab/ops.json` and `book/graph/mappings/vocab/filters.json`.
  - Do not invent new operation/filter names or assume cross-version stability without an explicit mapping.
- Treat the following core mappings as important intermedaite representations (IR):
  - Vocab tables: `book/graph/mappings/vocab/{ops.json,filters.json,attestations.json}`.
  - Op-table, tag layouts, anchors: `book/graph/mappings/op_table/`, `tag_layouts/`, `anchors/`.
  - System profiles: `book/graph/mappings/system_profiles/{digests.json,attestations.json,static_checks.json}`.
  - Runtime and lifecycle manifests: `book/graph/mappings/runtime/{expectations.json,lifecycle.json}` plus `runtime/{traces,lifecycle_traces}/*.jsonl`.

When artifacts, runtime behavior, and substrate texts disagree, treat that as an open modeling or tooling bug. Record and bound the discrepancy; do not resolve it by averaging stories.

## Where to work

Unless directed otherwise, work only in `book/`, following the layered guidance there.

## Things to avoid

- Do not:
  - Move, copy, or check in anything from `dumps/Sandbox-private/` into tracked directories.
  - Treat external knowledge (docs, blogs, your own model weights) as authoritative over the substrate and mappings for this host.
  - Introduce new mapping JSONs or change schemas under `book/graph/mappings/` without updating metadata and checking all known consumers.
  - Hand-edit stable mapping JSONs under `book/graph/mappings/`; extend or add generators (for example under `book/graph/mappings/*/`) and regenerate from experiments or validation outputs instead.
  - Hide harness failures, decoder errors, or apply gates (e.g., `sandbox_apply` returning `EPERM`); record them in the relevant `Report.md` / `Notes.md`.

## Testing loop

Your primary test loop is:

```
source .venv/bin/activate
make -C book test
```

This single entrypoint runs the Python sanity harness and builds the Swift graph tools. Do not use other runners (e.g., direct `pytest`) as the default path.
