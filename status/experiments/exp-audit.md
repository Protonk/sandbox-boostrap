# Experiments audit

This document summarizes what `book/experiments/*` are doing as a population: what they appear to be for, how they are structured, which parts are stable vs exploratory, and where expectations for future experiments are emerging.

It merges two perspectives:

- the **conceptual view** from `exp-assessment.md` (what experiments are trying to accomplish), and
- the **mechanical audits** from `audits_combined.md` (what is actually present in Plans, Reports, `out/`, mappings, and tests).

The intent is to give future agents enough context to design, extend, or refactor experiments in a way that fits the project’s expectations.

---

## 1. What experiments are for (perceived role)

Taken together, the experiments for this Sonoma baseline behave like a lab for SANDBOX_LORE:

- At the **static layer**, clusters like `vocab-from-cache`, `node-layout`, `op-table-operation`, `op-table-vocab-alignment`, `tag-layout-decode`, `field2-filters`, `anchor-filter-map`, `probe-op-structure`, and `system-profile-digest` collectively aim to fix the shape of compiled profiles on this host:
  - Operation and Filter vocabularies.
  - Operation pointer table structure and bucket behavior.
  - Node tag layouts and the role of `field2`.
  - Anchor semantics and canonical system-profile digests.
- At the **runtime and lifecycle edge**, experiments such as `runtime-checks`, `sbpl-graph-runtime`, and `entitlement-diff` try to turn a curated subset of those static profiles into “golden” SBPL ↔ PolicyGraph ↔ runtime triples and entitlement-driven deltas, while explicitly documenting where apply gates and environment quirks block clean stories.
- **Kernel-facing work** (`kernel-symbols`, `symbol-search`) is slowly converging on how PolicyGraphs are dispatched inside `BootKernelExtensions.kc`, so static graphs and vocab mappings can eventually be tied to concrete evaluator code without overclaiming.

Across the suite, the shared ambition is:

- to compress the high-churn details of this one host into a disciplined set of **structural facts** and **cautiously labeled dynamic examples**; and
- to promote a small number of those into versioned, guardrailed mappings under `book/graph/mappings/*`, so the textbook can rely on them as canonical evidence rather than on ad hoc RE notes.

---

## 2. How experiments are structured today

From both the assessment and the scaffold census:

- Each experiment is a **small research cluster** rooted at `book/experiments/<name>/`, with:
  - `Plan.md` (purpose, scope, steps, deliverables),
  - `Notes.md` (dated log), and
  - `ResearchReport.md` (baseline, methods, current status, expected outcomes).
- Nearly all emit machine-readable artifacts in an `out/` directory (usually JSON) capturing:
  - inventories (field2/anchors/tags),
  - histograms and summaries,
  - manifests of vocab, alignments, or system-profile structure.
- The baseline is explicitly **host-bound**:
  - macOS 14.4.1 (23E224), Apple Silicon, SIP enabled.
  - Experiments treat their findings as specific to this PolicyGraph + vocabulary snapshot, not as cross-version lore.
- **Static decoding dominates**:
  - SBPL → compiled profile format,
  - Operation pointer tables,
  - node tags and `field2`,
  - vocab extraction from dyld and system blobs,
  - with semantic/lifecycle claims clearly marked as partial or brittle.
- Experiments are tightly coupled to shared mappings under `book/graph/mappings/*`:
  - vocab (`vocab/ops.json`, `vocab/filters.json`),
  - op-table and alignment files,
  - tag layouts,
  - anchor maps,
  - system-profile digests,
  and either consume or produce these as part of a larger static atlas.
- **Guardrails** are a recurring pattern:
  - Stable mappings (vocab, tag layouts, system digests, first-pass anchor maps) are backed by tests such as `tests/test_mappings_guardrail.py` or local helpers like `check_vocab.py`.
- **Cross-experiment reuse** is intentional:
  - Outputs from one cluster (`probe-op-structure`, `field2-filters`, `node-layout`, `op-table-operation`, `vocab-from-cache`) feed others (`anchor-filter-map`, `op-table-vocab-alignment`, `system-profile-digest`, runtime harnesses), forming a shared evidence pipeline.
- Only a **minority** of experiments are runtime-heavy; they treat runtime results as fragile, carefully scoped, and always annotated with blockers (EPERM, harness quirks).
- Kernel and entitlement/lifecycle work are treated as **provisional**: dispatcher candidates and entitlement-driven behaviors are recorded as hypotheses, not facts.

This structural discipline is already close to what `book/experiments/AGENTS.md` should codify.

---

## 3. Lifecycle and maturity

If we read Plans and ResearchReports (rather than trusting string heuristics), experiments fall into a small number of lifecycle bands:

**3.1 Stable mappings with guardrails**

- `vocab-from-cache`  
  - Publishes `book/graph/mappings/vocab/ops.json` and `filters.json` as `status: ok` for this host, with provenance; adds `check_vocab.py` as a guardrail. Marked complete.
- `tag-layout-decode`  
  - Publishes `tag_layouts/tag_layouts.json` (per-tag layouts for literal/regex-bearing nodes) and describes a guardrail in `tests/test_mappings_guardrail.py`. Decoder uses these layouts.
- `system-profile-digest`  
  - Publishes `system_profiles/digests.json` (op-table entries, tag counts, sections for `airlock`, `bsd`, `sample`) with a guardrail test.
- `anchor-filter-map`  
  - Publishes `anchors/anchor_filter_map.json` (anchor→Filter-ID mapping) and notes a guardrail in `tests/test_mappings_guardrail.py`. First-pass map; ambiguous anchors are explicitly labeled.

These experiments have:

- clearly stated baselines,
- concrete mappings under `book/graph/mappings/*`, and
- tests that assert at least presence and basic shape.

**3.2 Structural mappings/alignments (no explicit guardrail yet)**

- `op-table-vocab-alignment`  
  - Produces `out/op_table_vocab_alignment.json`, tying op-table buckets to operation IDs and filter IDs from vocab. Treated as a host-specific alignment layer; no tests mentioned.
- `node-layout`  
  - Establishes the modern profile layout and emits `out/summary.json` with op-table, node-region, and literal-pool structure; does not publish a standalone mapping or mention tests.
- `op-table-operation`  
  - Produces `out/summary.json`, `out/op_table_map.json`, `out/op_table_signatures.json` for bucket behavior; explicitly avoids defining a full Operation Vocabulary Map and leaves that to other layers.

These are mature structural experiments whose results feed mapping work, but they themselves are not yet “canonical artifacts” in `book/graph/mappings/*`.

**3.3 Exploratory/static work**

- `field2-filters`  
  - Builds a `field2` census (`out/field2_inventory.json`, `out/unknown_nodes.json`), demonstrates vocab-aligned low IDs and high unknowns, and records negative probe results; explicitly states that no guardrails were added and that mapping remains open.
- `probe-op-structure`  
  - Improves slicing and anchor scans, records tag inventories and layout hypotheses, and acknowledges that literal/regex operands are still not fully decoded; guardrails are mentioned only as a future goal.
- `kernel-symbols`  
  - Catalogs string and symbol references for sandbox/AppleMatch/mac_policy in the kernelcache; treats outputs as inventory, not as proven dispatcher mappings.
- `symbol-search`  
  - Extends the kernel work by chasing AppleMatch imports and MACF hooks, but so far only finds negative/ambiguous results; no `out/` artifacts or guardrails.

These experiments are about **mapping the search space** (what exists, what looks promising, where heuristics break) rather than publishing stable mappings.

**3.4 Runtime and entitlement experiments**

- `entitlement-diff`  
  - Builds signed/unsigned binaries and extracts entitlements; is currently blocked on generating per-entitlement sandbox profiles and running probes; no mappings or guardrails yet.
- `runtime-checks`  
  - Defines an expected runtime matrix, runs probes via wrappers, and records EPERM behavior and harness quirks; guardrails are described as desired but not yet implemented.
- `sbpl-graph-runtime`  
  - Shows that strict `(deny default)` profiles kill probes even with allowances; concludes that more relaxed profiles are needed to get clean allow/deny triples; no runtime guardrails yet.

For these, the correct lifecycle label is “blocked/brittle runtime scaffolding,” not “stable semantic witness.”

---

## 4. Evidence, artifacts, and mappings

### 4.1 Evidence types and artifacts

Experiments tend to work over a small set of evidence types:

- Compiled SBPL profiles (`*.sb.bin`) from:
  - Tiny synthetic profiles under `book/experiments/*/sb/`.
  - Canonical system blobs from `book/examples/extract_sbs/build/profiles/`.
- Dyld shared cache slices (Sandbox.framework / libsandbox) for vocab extraction.
- Kernelcache (`BootKernelExtensions.kc`) and Ghidra projects for kernel symbol/string work.
- Runtime traces and microprofiles produced by SBPL-wrapper-based harnesses.

The evidence/artifact audit highlighted how well these artifacts are wired into the reports:

- Many core `out/` artifacts are described and used directly in Reports (e.g., `field2_inventory.json`, `tag_histogram.json`, `op_table_signatures.json`).
- Some important artifacts are present but not mentioned:
  - `entitlement-diff`: `entitlement_manifest.json`, the unsigned entitlements plist.
  - `kernel-symbols`: `script.log`, `targets.json`, `trace.log` under `out/.../kernel-symbols/`.
  - `probe-op-structure`: analysis and literal-scan JSONs and summaries.
  - `runtime-checks`: recompiled `airlock`/`bsd` blobs, runtime profiles (`*.runtime.sb`), and `runtime_results.json`.
  - `sbpl-graph-runtime`: compiled SBPL binaries for the test profiles and `triples_manifest.json`.

Those omissions matter because the project expects every substantive claim to be traceable to a concrete artifact. Future updates should make sure each such file is named and briefly described in the ResearchReport.

### 4.2 Mapping status and usage

Mappings under `book/graph/mappings/*` are the pieces the textbook is allowed to treat as structural facts (subject to their `status`):

- **Produced mappings**
  - `vocab-from-cache`: `vocab/ops.json` and `vocab/filters.json` as `status: ok` for this host.
  - `tag-layout-decode`: `tag_layouts/tag_layouts.json` plus layout hints tied to anchors and tags.
  - `system-profile-digest`: `system_profiles/digests.json` aggregating system blobs.
  - `anchor-filter-map`: `anchors/anchor_filter_map.json`, based on `field2` inventories, anchor hits, and vocab.
  - Alignment/mapping helpers (`op_table_vocab_alignment`, tag layouts, anchor_field2 hints) that knit experiments together.
- **Consumed mappings**
  - Many experiments (`node-layout`, `op-table-operation`, `field2-filters`, `probe-op-structure`, kernel work) consume vocab and system-profile mappings as constraints.

The audit confirmed that:

- Vocab mappings are explicitly called out as `status: ok` with provenance (good).
- Tag layouts and anchor maps are described as “best-effort” and “first-pass,” with open questions and plans to revisit (good).
- Alignment artifacts (op-table ↔ vocab) are treated carefully in code, but their statuses are less visible in prose.
- Some experiments consume mappings that may have mixed entry statuses without acknowledging that distribution; this should be tightened so that partial/brittle entries don’t get silently promoted to invariants.

---

## 5. Runtime and kernel work

Runtime and kernel experiments are explicitly in-progress and constrained by the host environment:

- **Runtime**
  - `runtime-checks` and `sbpl-graph-runtime` document:
    - EPERM from `sandbox_apply` when trying to apply certain platform/system profiles.
    - Strict profiles killing probes even after adding allowances.
    - Harness evolution from `sandbox-exec` to wrapper-based runners, including rough edges.
  - They produce useful runtime artifacts (expected matrices, actual results, runtime profiles), but the mismatch between expectations and outcomes means they cannot yet serve as “golden” semantic witnesses.
  - `entitlement-diff` is still blocked on profile derivation from entitlements.

- **Kernel**
  - `kernel-symbols` and `symbol-search`:
    - Use Ghidra to find sandbox/AppleMatch/mac_policy strings/symbols.
    - Document “no callers” and “no references” situations rather than trying to paper them over.
    - Keep potential op-table or dispatcher data structures as candidates, not confirmed facts.

The audits reinforce the project’s invariant that **semantic and lifecycle clusters are in-progress** and must be presented as hypotheses with clear validation status.

---

## 6. Reproducibility and rerunability

The reproducibility audit confirms a pattern that the docs already hint at:

- Most experiments have one or more scripts (`*.py`, sometimes `*.sh`) that can be treated as entry points:
  - Structural: `op-table-operation/analyze.py`, `node-layout/analyze.py`, `probe-op-structure/analyze_profiles.py`.
  - Vocab: `vocab-from-cache/harvest_ops.py`, `harvest_filters.py`.
  - Runtime: `runtime-checks/run_probes.py`.
- Only a few Experiments explicitly document how to run these scripts in their Reports or Plans:
  - `op-table-operation` and `vocab-from-cache` are closest to “documented lab protocols.”
- External dependencies are clustered and predictable:
  - Ghidra: for kernel and some deep format work.
  - SBPL-wrapper and `sandbox-exec`: for runtime probes.
  - Codesign and Swift tooling: for entitlement and dyld-cache experiments.

For the eventual `AGENTS.md`, a concrete expectation emerges:

- **Every experiment that matters long-term should include a short “How to run this” section in its Plan or Report, with at least one concrete command line using its scripts.**

---

## 7. Blockers and environment hazards

The blockers audit provides a taxonomy of how experiments get stuck:

- **Runtime apply gates**
  - `sandbox_init` / `sandbox_apply` returning EPERM when applying platform/system profiles or strict policies.
  - Affects `runtime-checks`, `sbpl-graph-runtime`.
- **Decoder limits**
  - Heuristic slicing or stride-12 parsing yielding `node_count=0` or ambiguous tag layouts.
  - Seen in `field2-filters`, `probe-op-structure`, and early `node-layout` passes.
- **Kernel/Ghidra limits**
  - Strings with no callers, incomplete analysis, ambiguous pointer-table usage.
  - Prominent in `kernel-symbols` and `symbol-search`, and noted in passing in `field2-filters`.
- **Tooling gaps**
  - `sandbox-exec` quirks, wrapper behavior, `sbsnarf` requiring absolute paths, etc.
  - Show up in `runtime-checks`, `sbpl-graph-runtime`, `op-table-operation`, `entitlement-diff`.

The positive behavior is that many experiments already record these blockers in Notes and Reports. The audits suggest raising that to an explicit norm:

- **Blockers are first-class results.** Agents should not erase them; they should log them (with enough context to reproduce) and update the ResearchReport’s status and expected outcomes accordingly.

---

## 8. Project-level goals and expectations

Based on both the conceptual assessment and the audits, the project’s expectations for `book/experiments/` can be summarized as:

- **Lifecycle and maturity**
  - Make it clear which phase an experiment is in: scaffolded, data pass, mapping published, guardrailed, or blocked.
  - Don’t claim “done” until mappings are published and guardrailed (for static work) or until runtime semantics are consistent and explained (for runtime work).

- **Evidence levels and validation policy**
  - Treat mapping `status` fields (`ok`, `partial`, `blocked`, `brittle`) as part of the meaning of the result.
  - Avoid silently upgrading `partial` or `brittle` results to structural facts in prose or in chapter usage.

- **Concept inventory coverage**
  - Each experiment should be able to say which concept clusters it is witnessing (Operations, Filters, PolicyGraph structure, Profile Layers, Runtime Lifecycle, Kernel Dispatch, Containers, Extensions, Entitlements, etc.).
  - Structural experiments should be grounded in SBPL and compiled-profile views; kernel and runtime experiments should be explicit about which concepts they are probing and what remains unknown.

- **Integration with the book**
  - Experiments that publish stable mappings or runtime case studies should be candidates for inclusion in chapter figures and the addendum’s experiment index.
  - If an experiment is meant to remain internal scaffolding, its Report should say so.

- **Guardrail and test conventions**
  - Publishing a mapping or runtime artifact that others will depend on implies adding a guardrail:
    - presence checks (file exists),
    - shape checks (keys, counts, basic invariants),
    - and, where appropriate, value checks (counts, IDs).

- **Role boundaries vs `examples/` and `api/`**
  - `book/experiments/` is for research clusters and mapping work, not for polished teaching demos (those live in `book/examples/`) or shared tooling (which lives in `book/api/`).
  - Experiments should reuse shared APIs (`book.api.decoder`, SBPL wrapper, Ghidra connector) rather than reimplementing them locally.

- **Runtime vs static vs kernel work**
  - Static mapping experiments are expected to reach `status: ok` with guardrails.
  - Runtime and kernel experiments are allowed to stay `partial` or `blocked`, but must:
    - record blockers clearly,
    - avoid overstating certainty,
    - and tie any hypotheses to specific artifacts.

- **Agent behavior and logging**
  - Agents should log dead ends, environment blockers, and negative results in `Notes.md` and summarize them in `ResearchReport.md`.
  - Updates should preserve provenance (what changed, why, and on which host baseline).

These expectations are the raw material for a future `book/experiments/AGENTS.md` file that gives concrete, experiment-level guidance to agents working in this directory.

---

## 9. Scripted audit snapshots

For convenience, the mechanical audit results are summarized here:

- **Reproducibility audit**
  - 14 experiments scanned.
  - Most have entry scripts; very few document run commands explicitly.
  - External dependencies cluster around Ghidra, SBPL-wrapper/`sandbox-exec`, codesign, `dsc_extractor`, and `file_probe`.

- **Evidence & artifact audit**
  - 14 experiments scanned.
  - Several have `out/` artifacts that are not mentioned in their Reports; these should be linked in future edits.

- **Heuristic lifecycle audit**
  - 14 experiments scanned.
  - Stage counts based on simple file/substring heuristics: `mapping_published`: 5, `guardrailed`: 7, `data_pass`: 1, `scaffolded`: 1.
  - These are useful as a coarse sanity check but should not override doc-based classifications.

- **Mapping status audit**
  - 14 experiments scanned.
  - Confirms that mapping responsibility is concentrated in a small subset of experiments (vocab, tag layouts, system digests, anchor maps, alignment helpers), while most other experiments consume those mappings or explore open questions.*** End Patch```ṋябрassistant to=functions.apply_patchсионary="{\"command\":\"sed -n '1,260p' status/experiments/exp-audit.md\",\"timeout_ms\":10000,\"workdir\":\"/Users/achyland/Desktop/SANDBOX_LORE\"}"} ***!
