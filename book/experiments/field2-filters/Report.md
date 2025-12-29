#+#+#+#+#+#+#+#+━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Field2 ↔ Filter Mapping — Research Report

Status: complete (negative)

## Purpose and closure posture

This experiment set out to understand the third u16 slot carried by compiled PolicyGraph nodes on this host baseline. Historically this slot was discussed as “field2”; in this repo it is now named structurally as `filter_arg_raw`. The goal was to connect that u16 to the host Filter vocabulary where appropriate, and to determine whether the remaining high/out-of-vocab values have interpretable semantics (for example, a flag split or a stable auxiliary identifier).

The experiment is closed as a negative result. On this host (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`), we have exhausted (1) SBPL-based synthesis and perturbation, and (2) kernel-side structure hunting in the sandbox evaluator path, without finding evidence for a kernel-side hi/lo split or a stable semantic interpretation of the remaining out-of-vocab u16 values. The u16 is read and propagated as a raw u16 by the evaluator’s reader helpers. The only evidence-backed interpretation boundary we keep is structural: the u16 slot exists (or not) depending on tag layout; and when the tag’s u16 role is “filter vocabulary id”, the value may or may not resolve in the host filter vocabulary.

This closure is not “we learned nothing.” We learned a stable set of structural relationships and constraints on this host, and we updated the repo’s IR to preserve those relationships deterministically.

## World, inputs, and evidence model

All claims in this report are about the single frozen world `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`. The primary evidence is compiled profiles and host-bound mappings.

Canonical vocabulary mappings live at `book/graph/mappings/vocab/filters.json` and `book/graph/mappings/vocab/ops.json` (status: ok). Canonical profiles used throughout this work are `book/graph/concepts/validation/fixtures/blobs/{airlock,bsd,sample}.sb.bin`. Experimental probes (SBPL sources and compiled blobs) live under `book/experiments/field2-filters/sb/` and `book/experiments/field2-filters/sb/build/`.

The experiment’s primary outputs are `book/experiments/field2-filters/out/field2_inventory.json` (per-profile histograms, tag counts, and hi/lo census) and `book/experiments/field2-filters/out/unknown_nodes.json` (concrete unknown/high nodes with fields, fan-in/out derived from the current edge assumptions, and op reach when available).

Kernel-side evidence is sourced from Ghidra analysis outputs under `dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/`, driven by scripts under `book/api/ghidra/scripts/`.

## Approach (what we did)

We approached “field2” as a structural slot whose meaning must be inferred from repeated host witnesses. The work progressed in four strands that fed one another.

First, we established and reused a tag-aware structural decoder and tag layout map. The repo’s tag layout mapping for this world is `book/graph/mappings/tag_layouts/tag_layouts.json` (regenerated from the canonical corpus via `book/graph/mappings/tag_layouts/generate_tag_layouts.py`). On this host baseline the decoder’s strongest structural witness is an 8-byte node record framing, with `field2` surfaced as the third u16 in each record (u16[2]). The tag layout map makes this framing explicit (record size, edge field indices, payload field indices) so later work can talk about “the u16 slot” without relying on ad hoc record parsing.

Second, we harvested inventories over canonical blobs and probe blobs. The scripts `book/experiments/field2-filters/harvest_field2.py` and `book/experiments/field2-filters/unknown_focus.py` aggregate, for each profile, the multiset of observed `filter_arg_raw` u16 values, their tag distributions, and (where decode makes it possible) their attachment to literals/anchors and to op reach. The inventory is intentionally descriptive: it records which values appear, where they appear (tag context), and how often; it does not attempt to assign semantics.

Third, we ran a set of SBPL probe families designed to surface and isolate the out-of-vocab/high u16 values seen in system profiles. The probe families include “flow-divert require-all” variants, system-fcntl variants, and attempts to reproduce bsd-tail highs in smaller contexts. A repeating pattern emerged: many simplified probes collapse to a generic low-ID scaffolding and do not reproduce the system-only highs; conversely, richer mixed probes sometimes preserve a specific unknown (notably the flow-divert 2560 value) under a stable predicate combination.

Fourth, we hunted for kernel-side structure and transforms. Using the extracted arm64e sandbox kext (`/tmp/sandbox_arm64e/com.apple.security.sandbox`) and headless Ghidra tooling, we identified u16 reader helpers (`__read16`) and inspected the evaluator (`_eval`) and its reachable neighborhood for (a) bit masking/splitting of the u16 (e.g., `0x3fff`, `0x4000`) and (b) any blessed kernel-side “node struct” evaluator that would justify treating the blob as a directly indexed struct array at runtime. The reader helper loads a u16 and stores it without masking; `_eval` contains other masks (e.g., `0x7f`, `0xffffff`, `0x7fffff`) but not the hypothesized hi/lo masks for `filter_arg_raw`. A dedicated “node struct scan” over all functions reachable from `_eval` found no clear fixed-stride `[byte + ≥2×u16]` kernel node layout. This supports the “bytecode VM over a profile blob” model for this host rather than a simple, exposed node-array walker.

## Results (what we learned)

### Low values align with the host filter vocabulary

Across the canonical `bsd` and `sample` profiles, low u16 values in the payload slot correspond directly to filter IDs in `book/graph/mappings/vocab/filters.json`. The inventory includes repeated witnesses for common filter IDs such as path/name/socket classes and system-specific filters (`right-name`, `preference-domain`, iokit-related filters, and others). This is the positive core: when a tag’s payload u16 is used as a filter vocabulary id, the mapping is stable and matches the host vocabulary.

### A bounded set of out-of-vocab/high values persists

The canonical profiles and probe corpus produce a bounded set of out-of-vocab/high values, clustered by tag context and by profile context. The salient clusters are:

`flow-divert` probes: `filter_arg_raw=2560` (`0x0a00`) and `2816` (`0x0b00`) are now treated as characterized (triple-only) and are excluded from the “unknown” census; see `book/experiments/flow-divert-2560/Report.md`. Other out-of-vocab values surfaced in the same probe family (for example `12096`) remain in the unknown set.

`bsd` cluster retired: under the stride=8 framing, the canonical `bsd` profile’s `field2` payloads align fully with the host filter vocabulary; the earlier bsd “tail” (`0x4114`) and tag26 highs were decode-framing artifacts from the previous stride=12 approximation.

`airlock` survivors: the canonical `airlock` profile still contains a small set of out-of-vocab payloads in tags whose u16[2] slot is treated as a filter vocabulary id on this host (notably `165` and `49171`).

`sample` and probe sentinels: `256`, `1281`, and `3584` recur in the canonical sample and in probe-like contexts; they remain “structurally witnessed, semantically opaque” for this world.

The experiment treats these values as “structurally bounded but semantically opaque” for this world. We keep their contexts and counts; we do not assert a kernel-consumed semantic split.

### Kernel-side structure hunt is negative for u16 splitting

The kernel-side work in `dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/` supports two negative conclusions.

First, the u16 reader helper (`__read16`) loads and forwards the u16 without applying masks or bitfield extracts. Second, neither `_eval` nor its reachable neighborhood contains the hypothesized `0x3fff`/`0x4000` masks that would indicate a stable hi/lo split of `filter_arg_raw`. This does not prove that no semantics exist, but it eliminates a broad and previously plausible hypothesis space.

Separately, a dedicated scan (`kernel_node_struct_scan.py`) over all functions reachable from `_eval` found no blessed kernel “PolicyGraph evaluator” that can be treated as a simple node-array walker. This constrains future semantics work: even if the blob is structurally consistent with an 8-byte record framing for decoding, the kernel’s execution path on this host still looks more like a bytecode VM over the profile blob than a direct, public “struct node” evaluator.

## How the repo now preserves the result (structural contract)

This experiment produced two repository-level contract improvements that reduce ambiguity for future work without prematurely enforcing cross-world assumptions.

First, u16 role is now explicit per tag for this world. The mapping `book/graph/mappings/tag_layouts/tag_u16_roles.json` declares, for each tag in the canonical corpus, whether the payload u16 slot is intended to be treated as a filter vocabulary id (`filter_vocab_id`) or as an opaque argument u16 (`arg_u16`). This keeps the “unknown” census scoped to tags where out-of-vocab payloads are meaningfully interpreted as “unknown filter IDs” rather than conflating all tags’ u16[2] slots.

Second, the decoder now exposes structure with provenance rather than silently guessing. `book/api/profile/decoder/` remains permissive, but it now attaches `filter_arg_raw`, `u16_role`, and (when applicable) `filter_vocab_ref` / `filter_out_of_vocab` directly on decoded nodes, and it records provenance for layout selection and literal reference recovery. The decoder does not enforce “unknown-but-bounded”; discovery stays possible.

To protect the learned tag/layout/role relationships on this host without freezing a closed unknown inventory, we added a lightweight validation job and guardrail test. The validation job `structure:tag_roles` lives in `book/graph/concepts/validation/tag_role_layout_job.py` and is registered via `book/graph/concepts/validation/registry.py`. It runs on the pinned canonical corpus and verifies the two structural invariants: observed tags have declared roles, and tags whose roles imply a payload slot have layouts. It also reports vocab hit/miss counts and fallback usage, but it does not fail merely because values are out-of-vocab.

The guardrail test `book/tests/test_field2_unknowns.py` pins the current out-of-vocab payload set observed in `unknown_nodes.json`, scoped to `u16_role=filter_vocab_id` tags only. Flow-divert triple-only payloads 2560 and 2816 are asserted separately and are intentionally excluded from the unknown set.

## Non-claims and limitations

This report does not claim a semantic interpretation of out-of-vocab/high values such as 2560, 2816, 12096, 49171, or 3584. It does not claim that these values are sentinels, indices, or flags; it claims only that they are observed, context-bounded u16 payloads in compiled profiles on this host (with 2560/2816 being characterized only by their triple-only structural witness).

This report also does not claim semantic completeness for the tag layout map. `book/graph/mappings/tag_layouts/tag_layouts.json` is a structural, canonical-corpus-derived framing map; it improves decoder stability and repeatability but does not, by itself, establish semantic meaning for each tag’s payload.

Finally, platform/runtime gates (e.g., inability to apply certain system profiles) mean that this experiment is predominantly static. Runtime semantics, if they exist, are not established here.
