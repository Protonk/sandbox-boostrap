# Experiments audit bundle

This document pulls together the various audits we ran over `book/experiments/*` and distills what they say about how experiments behave as a group: what is stable, what is still exploratory, and where expectations are implicit rather than written down.

## High-level picture

- There is a small set of **stable, guardrailed mappings** that form the backbone of the static atlas on this host:
  - `vocab-from-cache` (Operation/Filter vocabularies, `status: ok`, with `check_vocab.py` as a guardrail).
  - `tag-layout-decode` (tag layouts for literal/regex-bearing nodes, with a guardrail under `tests/test_mappings_guardrail.py`).
  - `system-profile-digest` (canonical system profile digests with a guardrail).
  - `anchor-filter-map` (first-pass anchor→Filter-ID mapping, with a guardrail).
- Several **structural experiments** are mature but still experiment-local: `node-layout`, `op-table-operation`, and `op-table-vocab-alignment` have rich data and alignment artifacts, but only the vocab and tag-layout mappings they feed are treated as canonical.
- **Runtime and entitlement experiments** (`runtime-checks`, `sbpl-graph-runtime`, `entitlement-diff`) are still blocked or brittle on this host; they document apply gates, EPERM behavior, and harness issues but do not yet provide stable runtime guardrails.
- **Reproducibility in docs is thin**: most experiments rely on implicit scripts; only a couple (`op-table-operation`, `vocab-from-cache`) clearly document how to rerun themselves.
- **Evidence ↔ artifact linkage** is uneven: some `out/` artifacts, especially runtime profiles, recompiled blobs, and kernel logs, are not mentioned in their reports.
- **Blockers are common** and reasonably well-documented in several experiments (runtime apply gates, decoder limits, Ghidra “no callers”), but are absent in others that are clearly incomplete.
- **Mapping status discipline** varies: vocab mappings are explicitly `status: ok`; tag layouts and anchor maps are “best-effort”; some experiments consume mappings with mixed statuses without acknowledging that in prose.

## Shared traits and goals (from exp-assessment)

Across the experiment population:

- Each experiment is a small research cluster rooted at `book/experiments/<name>/` with `Plan.md`, `Notes.md`, `ResearchReport.md`, and usually an `out/` directory.
- They share a fixed host baseline (macOS 14.4.1 / 23E224, Apple Silicon, SIP enabled) and treat that as the world for structural claims.
- Static decoding and mapping work dominates: compiled profiles, op-tables, node tags, `field2`, and dyld/kernel artifacts are primary evidence.
- Shared mappings live under `book/graph/mappings/*` and are expected to be guarded by tests when they are treated as stable.
- Runtime and kernel experiments are explicitly provisional; they record blockers rather than pretending to have complete answers.
- Experiments reuse each other’s outputs (especially `vocab-from-cache`, `node-layout`, `op-table-operation`, `probe-op-structure`, `field2-filters`) to build a coherent static atlas.

The project’s goals for experiments follow from this:

- Make the **lifecycle and maturity** of an experiment explicit (scaffolded → data pass → mapping published → guardrailed → referenced in chapters/addendum).
- Tie experiments clearly to **evidence levels** (empirical, heuristic, speculative) and `status` tags on mappings.
- Ensure experiments state which **concept clusters** they witness (Operations, Filters, PolicyGraph structure, runtime lifecycle, kernel dispatch, etc.).
- Clarify how experiments are expected to **feed into chapters**, examples, and the addendum’s experiment index.
- Establish norms around **guardrails**, **role boundaries** (vs `examples/` and `api/`), and **logging of blockers**.

## Lifecycle and maturity (doc-based)

Reading the Plans and ResearchReports (ignoring heuristic string scans), experiments fall into a few maturity bands:

- **Stable mappings with guardrails**
  - `vocab-from-cache` – Harvests operation and filter vocab from the dyld cache, publishes `ops.json`/`filters.json` with `status: ok`, and adds `check_vocab.py` as a guardrail. The report marks the experiment “complete.”
  - `tag-layout-decode` – Publishes `tag_layouts/tag_layouts.json` and notes a guardrail in `tests/test_mappings_guardrail.py`.
  - `system-profile-digest` – Publishes `system_profiles/digests.json` and adds a guardrail test.
  - `anchor-filter-map` – Publishes `anchors/anchor_filter_map.json` and describes a guardrail in `tests/test_mappings_guardrail.py`. The map is explicitly “first-pass” with ambiguous anchors noted.

- **Structural mappings or alignments (no explicit guardrail yet)**
  - `op-table-vocab-alignment` – Emits `out/op_table_vocab_alignment.json` as a host-specific alignment of op-table entries to vocab IDs, but does not claim tests.
  - `node-layout` – Defines the structural layout of modern profiles and emits `out/summary.json`; no mapping under `book/graph/mappings/` or guardrail is claimed.
  - `op-table-operation` – Produces `out/summary.json`, `out/op_table_map.json`, and `out/op_table_signatures.json` for bucket behavior, while explicitly deferring vocab mapping to other experiments.

- **Exploratory/static work**
  - `field2-filters` – Builds a rich `field2` census (`out/field2_inventory.json`, `out/unknown_nodes.json`) and documents negative/ambiguous results; explicitly says that no guardrails were added and that mapping remains open.
  - `probe-op-structure` – Improves slicing and anchor scans, introduces tag and literal inventories, and outlines next steps, but does not claim finished mappings or guardrails.
  - `kernel-symbols` – Records Ghidra string/symbol runs for the kernelcache; treats outputs as inventory, not as confirmed dispatchers or mappings.
  - `symbol-search` – Early RE on the PolicyGraph dispatcher/AppleMatch callers; no `out/` artifacts yet and no mappings.

- **Runtime and entitlement experiments (blocked or brittle)**
  - `entitlement-diff` – Compiles sample binaries and extracts entitlements, but is blocked on generating per-entitlement App Sandbox profiles; no runtime probes or mappings yet.
  - `runtime-checks` – Defines an expected runtime matrix and records results, but is constrained by `sandbox_apply`/`sandbox_init` EPERM behavior and noisy harnesses; guardrails are described as future work.
  - `sbpl-graph-runtime` – Shows that strict `(deny default)` profiles kill probes even after substantial allowances; concludes that allow/deny triples need more relaxed profiles and does not yet provide “golden” triples.

This doc-based view is more trustworthy than the heuristic “stage counts” and should guide future AGENTS guidance about when an experiment is allowed to call itself done.

## Scaffold census (structure and headings)

The scaffold census looked only at structure and headings:

- 14 experiments scanned; 11 clearly record the host baseline in their reports, 3 do so partially.
- ResearchReports tend to share a stable backbone of sections:
  - `Purpose`
  - `Baseline and scope` (or equivalent)
  - `Plan (summary)`
  - `Current status`
  - `Expected outcomes`
- Plans typically include some form of “Scope and setup” plus “Deliverables,” although the level of detail varies.

This suggests that new experiments should follow the same skeleton, and that `AGENTS.md` for `book/experiments/` can safely assume this shape.

## Reproducibility and rerunability

The reproducibility audit inspected Plans/Reports for run instructions and scanned directories for scripts:

- Only a couple of experiments both provide entry scripts **and** document how to run them:
  - `op-table-operation` – Has `analyze.py` and includes concrete “compile and decode” instructions.
  - `vocab-from-cache` – Has `harvest_ops.py` / `harvest_filters.py` and describes how the dyld cache was extracted and harvested.
- Many experiments ship scripts but have no explicit “Run:” section:
  - `field2-filters`, `node-layout`, `op-table-vocab-alignment`, `probe-op-structure`, `runtime-checks` all have local helpers (`*.py`, `*.sh`) but rely on agents inferring usage from filenames.
- External dependencies appear in a focused way:
  - Ghidra: `field2-filters`, `kernel-symbols`, `symbol-search`.
  - SBPL-wrapper / `sandbox-exec`: `op-table-operation`, `runtime-checks`, `sbpl-graph-runtime`.
  - Codesign / sandbox-exec: `entitlement-diff`.
  - `dsc_extractor` / dyld cache: `vocab-from-cache`.

For `AGENTS.md`, this argues for a norm like: “Every experiment that expects to be rerun should include a short ‘How to run this experiment’ section with explicit commands.”

## Evidence and artifacts

The evidence/artifact audit compared what the reports mention with what actually lives in `out/`:

- In many experiments, core `out/` artifacts are mentioned and explained (e.g., `field2_inventory.json`, `tag_histogram.json`, `op_table_signatures.json`).
- A few experiments have important `out/` artifacts that are never named in their ResearchReports:
  - `entitlement-diff` – `out/entitlement_manifest.json`, `entitlement_sample_unsigned.entitlements.plist`.
  - `kernel-symbols` – kernel-symbols `script.log`, `targets.json`, `trace.log`.
  - `probe-op-structure` – `analysis.json`, `literal_scan.json`, `summary.json`, `tag_bytes.json`.
  - `runtime-checks` – recompiled `airlock`/`bsd` blobs and all `runtime_profiles/*.runtime.sb` plus `runtime_results.json`.
  - `sbpl-graph-runtime` – compiled SBPL binaries (allow/deny profiles) and `triples_manifest.json`.

Those artifacts clearly mattered during the work and are likely to matter to future agents; they should be referenced explicitly in the reports so claims and evidence stay linked.

## Blockers and failure modes

The blockers audit searched Notes/Reports for characteristic failure phrases and grouped them by type:

- Common blocker types:
  - `kernel_or_ghidra_limit` – string references with no callers, incomplete analysis, ambiguous pointer tables (e.g., `kernel-symbols`, `symbol-search`).
  - `tooling_gap` – limitations of `sandbox-exec`, wrapper behavior, or decoder/slicing heuristics (e.g., `runtime-checks`, `sbpl-graph-runtime`, `op-table-operation`, `entitlement-diff`).
  - `runtime_apply_gate` – `sandbox_init` / `sandbox_apply` returning EPERM on platform blobs or strict profiles (`runtime-checks`, `sbpl-graph-runtime`).
  - `decoder_limit` – heuristic node parsing hitting `node_count=0` or ambiguous tag layouts (`field2-filters`, `probe-op-structure`).
  - `generic_blocker` – explicit “current blocker” or “blocked” language.
- Experiments that do a good job of logging blockers:
  - `runtime-checks` and `sbpl-graph-runtime` clearly record EPERM behavior and strict-profile failures.
  - `field2-filters` and `probe-op-structure` record decoder limitations and negative results.
  - `kernel-symbols` and `symbol-search` document Ghidra’s lack of callers or external matches.

For future work, the derived norm is: **if an experiment stalls on a known environment or tooling issue, that blocker should be recorded in Notes and summarized in the ResearchReport, even if the experiment remains incomplete.**

## Mapping status and usage

The mapping status audit looked at JSONs under `book/graph/mappings/*` and associated them back to experiments:

- Experiments producing mappings (via reported paths):
  - `anchor-filter-map` – `anchors/anchor_filter_map.json` (new), plus it relies on `anchors/anchor_field2_map.json` and `vocab/filters.json`.
  - `field2-filters` – consumes `vocab/filters.json` and helps refine interpretations but does not publish a new mapping.
  - `node-layout` and `probe-op-structure` – consume `vocab/ops.json` and influence later mapping work.
  - `system-profile-digest` – `system_profiles/digests.json`.
  - `tag-layout-decode` – `tag_layouts/tag_layouts.json` plus `anchor_field2_map`.
  - `vocab-from-cache` – `vocab/ops.json` and `vocab/filters.json`.
- Mapping `status` fields:
  - Vocab (`ops.json`, `filters.json`) is `status: ok` and called out as such in the `vocab-from-cache` report.
  - Tag layouts and anchor maps are described as best-effort, with open questions and a plan to revisit when better decoding or kernel evidence arrives.
  - Alignment artifacts (op-table↔vocab) are conservatively described as host-specific and versioned, but their `status` labels are less prominent in prose.

Going forward, experiments that publish or consume mappings should:

- Name the mapping files explicitly in their ResearchReports.
- State the expected `status` values (ok/partial/blocked/brittle) and what kind of evidence supports them.
- Avoid silently treating `partial` mappings as structural facts in chapters or examples.

## Scripted audit snapshots (for reference)

For completeness, we keep the high-level results of the scripted audits here:

- **Reproducibility audit**
  - Experiments scanned: 14.
  - Most have entry scripts; only `op-table-operation` and `vocab-from-cache` clearly document how to rerun them.
  - External dependencies cluster: Ghidra, SBPL-wrapper/`sandbox-exec`, codesign, `dsc_extractor`, `file_probe`.

- **Evidence and artifact audit**
  - Experiments scanned: 14.
  - Several experiments have unmentioned `out/` artifacts (listed above) that should be tied into their reports.

- **Heuristic lifecycle audit**
  - Experiments scanned: 14.
  - Stage counts (based purely on file presence and simple string matches): `mapping_published`: 5, `guardrailed`: 7, `data_pass`: 1, `scaffolded`: 1.
  - These numbers are useful as a rough sanity check, but doc-based classification is preferred for real decisions.

- **Mapping status audit**
  - Experiments scanned: 14.
  - Confirms which experiments produce or consume mapping JSONs; highlights that mapping responsibility is concentrated in a small subset (vocab, tag layouts, system digests, anchor maps, and alignment files).
