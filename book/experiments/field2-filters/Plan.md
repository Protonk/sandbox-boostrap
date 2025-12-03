# Field2 ↔ Filter Mapping Experiment (Sonoma host)

Goal: map decoder `field2` values to Filter IDs using the harvested filter vocabulary and targeted SBPL probes, then validate consistency across operations and profiles.

---

## 1) Scope and setup

**Done**

- Host baseline (OS/build, kernel, SIP) and canonical blobs recorded in `ResearchReport.md`.
- Vocab artifacts (`book/graph/mappings/vocab/filters.json`, `ops.json`) confirmed `status: ok` (93 filters, 196 ops).
- Canonical blobs for cross-check identified and used: `book/examples/extract_sbs/build/profiles/airlock.sb.bin`, `bsd.sb.bin`, `sample.sb.bin`.

**Upcoming**

- Keep baseline/version notes updated if the host or vocab artifacts change.
- Continue to carry the third node slot explicitly as `filter_arg_raw` with derived `field2_hi/field2_lo`; do not coerce high/unknown values into the existing filter vocabulary.

Deliverables:
- `Plan.md`, `Notes.md`, `ResearchReport.md` in this directory.
- A small helper script to collect `field2` values from decoded profiles.

## 2) Baseline inventory

**Done**

- Decoded canonical blobs and tallied unique `field2` values; baseline histograms recorded in `ResearchReport.md` and `Notes.md`. Refreshed the census to include hi/lo splits and per-tag counts, and pulled in mixed probe-op-structure builds to keep flow-divert and other richer shapes in view.
- Confirmed that many `field2` values align directly with filter vocab IDs (e.g., path/socket/iokit filters in `bsd` and `sample`), with high unknowns in `airlock`.

**Upcoming**

- Refine per-tag/per-op inventories using newer decoder layouts if needed.

Deliverables:
- Intermediate JSON/notes summarizing `field2` histograms and per-op reachable values.

## 3) Synthetic single-filter probes

**Done**

- Authored single-filter SBPL variants (subpath, literal, global-name, local-name, vnode-type, socket-domain, iokit-registry-entry-class, require-any mixtures) and compiled them under `sb/build/`; added probe-op-structure mixed-operation builds to keep the flow-divert 2560 signal available for comparison.
- Decoded each variant and recorded `field2` values; synthesized into `out/field2_inventory.json`.

**Upcoming**

- Design additional probes that reduce or alter generic path/name scaffolding (e.g., richer operations or more complex metafilters) to surface filter-specific `field2` values; keep richer network shapes when chasing flow-divert (simplified profiles collapsed field2 to low IDs and lost 2560; richer mixes like v4/v7 retain 2560). Treat hi/lo views as diagnostic only until kernel bitfields are known.

Deliverables:
- `sb/` variants + compiled blobs under `sb/build/`.
- Notes mapping filter name → observed `field2` value(s) with provenance.

## 4) Cross-op consistency checks

**Done (initial)**

- Checked that low `field2` IDs corresponding to path/name filters (0,1,3,4,5,6,7,8) behave consistently across system profiles and synthetic probes.
- Confirmed that system profiles (`bsd`, `sample`) reinforce the mapping for common filters (preference-domain, right-name, iokit-*, path/socket).

**Upcoming**

- Perform focused cross-op checks for less common filters once better probes or anchors are available; chase the flow-divert-specific field2 (2560) using richer network mixes, and any other high/unknown values by varying operations. Simplified dtracehelper/posix_spawn probes yielded only low IDs, so full-profile context may be required; adding mach to the mimic still did not surface high IDs. Use graph shape/position as the primary classifier, with `field2_hi/lo` treated as auxiliary evidence only.
- Flag and investigate any inconsistencies that appear as decoding improves.

Deliverables:
- Table of filter → `field2` with cross-op status (consistent/inconsistent).

## 5) System profile cross-check

**Done (baseline)**

- Inspected curated system profiles where literals strongly indicate filter type (paths, mach names, iokit properties) and confirmed that `field2` IDs match vocab entries where known.

**Upcoming**

- Use anchor mappings and updated tag layouts to deepen system-profile cross-checks, especially for high, currently-unknown `field2` values in `airlock` and the `bsd` tail (e.g., 170/174/115/109/16660 tied to dtracehelper/posix_spawn literals that did not reappear in isolated probes). Track `(tag, field2_hi, field2_lo)` distributions for these cases without assigning semantics yet.

Deliverables:
- Notes tying system-profile nodes to the inferred mapping.

## 6) Synthesis and guardrails

**Done (partial)**

- Summarized current understanding of `field2` behavior (generic path/name dominance, confirmed mappings for common filters, persistence of unknowns) in `ResearchReport.md` and `Notes.md`.
- Regenerated `out/field2_inventory.json` using shared tag layouts and anchor/filter mappings to keep inventories aligned with the global IR.

**Upcoming**

- Distill a stable `field2` ↔ filter-ID table for a small, high-confidence subset of filters; attempt to promote flow-divert-related values and high system-profile values only once additional probes and/or Sandbox.kext bitfields confirm them.
- Add a guardrail test/script that checks these mappings against synthetic profiles once the semantic layer is better understood; for now, keep high/unknown values in an “unknown-arg” bucket.
- Extend `ResearchReport.md` with any newly established mappings and explicit open questions, noting where conclusions rely on hi/lo heuristics versus kernel evidence.

## Current pushes (2026-02-11)

- Focused census: `unknown_focus.py` emits fan-in/out details for high/unknown nodes (out/unknown_nodes.json). Use tag layouts to keep edge positions consistent.
- Probes: `flow_divert_variant.sb` and `bsd_broader.sb` were added; both compiled (absolute paths required for sbsnarf) but collapsed to low IDs (no 2560 or bsd high values). Negative but documented.
- Next: keep classification shape-first, chase 2560 with additional mixed shapes if any surface, and prioritize Sandbox.kext bitfield masks once available.

## Next steps (2026-02-11)

- **Kernel masks (high value)**: Use Ghidra on `Sandbox.kext` (14.4.1, ARM64) to find the node evaluation loop and see how the third 16-bit payload is masked/split (`& 0x3FFF`, `& 0x4000`, shifts). Re-interpret high values (16660/2560/etc.) from those masks; this is the fastest path to authoritative semantics.
- **Graph shape (short-term)**: With tag layouts, extract fan-in/out and successor tags for high/unknown nodes (as in `out/unknown_nodes.json`); if edge layout ambiguity blocks deeper walks, note it. Look for shared tails/glue motifs across profiles to cluster unknowns by structure.
- **Probe refinement (bounded)**: Try at most 1–2 small perturbations of the `v4`/`v7` mixed network profiles (e.g., swap one op or metafilter) to see if 2560 survives. If they collapse to low IDs again, stop this branch and record the negative.
- **Guardrails**: Keep inventories tagging high/unknown as `UnknownFilterArg(field2_raw)` with hi/lo views; add a simple check to flag `hi != 0` in future dumps.
- **Documentation loop**: Log outcomes (including failed probes or blocked graph-walks) in `Notes.md`; promote to `ResearchReport.md` only when kernel masks or structural clustering yield grounded conclusions.

Deliverables:
- Updated `ResearchReport.md` and `Notes.md`.
- Guardrail test/script to prevent regressions.

## Follow-on after this run

- Primary next action: run the Ghidra pass on `Sandbox.kext` to find the node evaluator and any masks/shifts on the third 16-bit field; update this plan and `Notes.md` with any masks found, even if partial.
- Secondary: only if kernel masks remain unknown, consider one last mixed-network perturbation to probe the 2560 signal; abort if it collapses again.
- Keep high/unknown values in the `UnknownFilterArg` bucket until kernel semantics are known; add a lightweight warning in future inventories when `hi != 0` appears (currently only bsd’s 16660).

## Current kernel recon state (2026-02-11)

- Automated scans:
  - `kernel_field2_mask_scan` (sandbox blocks and full KC; masks 0x3fff/0x4000/0xc000/0x00ff/0xff00) → no hits.
  - `kernel_imm_search` for 0xa00, 0x4114, 0x2a00 across full KC → 0 hits each.
- Next manual pass (pending):
  - Use tag-switch candidates and sandbox-related functions to locate the evaluator in Ghidra.
  - Within those functions, look for loads of three u16 fields per node and any masking/shifting of the third payload; if found, dump disassembly and record masks/usage.
  - If still no masks, note functions inspected and pivot to other structural clues (op-table usage, node size arithmetic).
