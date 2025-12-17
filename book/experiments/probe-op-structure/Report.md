- world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5
- status: mapped-but-partial (structural, no runtime)
- primary outputs: out/analysis.json; out/anchor_hits.json; out/tag_inventory.json; out/tag_layout_hypotheses.json; out/literal_scan.json; out/tag_bytes.json
- upstream IR: book/api/decoder; book/graph/mappings/tag_layouts/tag_layouts.json; book/graph/mappings/vocab/filters.json
- downstream mappings: book/graph/mappings/anchors/anchor_filter_map.json; book/experiments/field2-filters/out/*
- guardrails: book/tests/test_anchor_filter_alignment.py; book/tests/test_mappings_guardrail.py

# Probe Op Structure – Research Report (Sonoma baseline)

## Quick orientation for new agents

This experiment walks a small matrix of probe profiles plus canonical system profiles and asks: **“Which Filters show up in `field2` on which nodes/tags, especially for concrete anchors like `/etc/hosts`, `/var/log`, `flow-divert`, and `IOUSBHostInterface`?”** It builds structural JSON views of op counts, tags, and `field2` histograms, and then a per-anchor map from literals → node indices → `field2` values using the shared decoder and tag layouts for this world.

You can **trust** the structural backbone: tag layouts for tags 0,1,3,5,7,8,17,26,27,166 come from `book/graph/mappings/tag_layouts/tag_layouts.json` (`status: ok`); `out/anchor_hits.json` is derived via `book/api/decoder` under those layouts; and mapped anchors in `book/graph/mappings/anchors/anchor_filter_map.json` are now enforced by a guardrail (`book/tests/test_anchor_filter_alignment.py`) that requires concrete witnesses in `anchor_hits.json`. What remains **partial** is the semantic meaning of many high `field2` values, several anchors that stay `status: "blocked"`, and any attempt to read deep semantics into generic scaffolding filters (`path`, `global-name`, `local-name`, `ipc-posix-name`, `remote`, `local`) from this experiment alone.

If you only look at three files to get oriented, start with:

- `book/experiments/probe-op-structure/Report.md` (this file)
- `book/experiments/probe-op-structure/out/anchor_hits.json`
- `book/graph/mappings/anchors/anchor_filter_map.json`

## Purpose

This experiment designs and decodes richer SBPL probe profiles to see how **`field2`** is used across operations, filters, and metafilters on this host. The aim is to move from “generic path/name dominance” in simple profiles toward **anchor‑aware, tag‑aware evidence** that ties:

- anchors (concrete literals like `/tmp/foo`, `flow-divert`, `preferences/logging`),
- decoded nodes (tags, edge wiring, `field2` payloads), and
- Filter vocabulary entries

into a reusable picture of how compiled PolicyGraphs encode filter arguments. All claims in this report are **mapped‑but‑partial**: they rely on concrete blobs and mappings, but the semantics of many high `field2` values and tags remain under exploration.

## Baseline & scope

- **World:** Sonoma baseline `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- **Vocab:** `book/graph/mappings/vocab/ops.json` and `filters.json` (both `status: ok` from `vocab-from-cache`).
- **Profiles:**
  - Probe SBPL variants under `book/experiments/probe-op-structure/sb/` with compiled blobs in `sb/build/`.
  - Canonical system blobs: `book/examples/extract_sbs/build/profiles/{airlock,bsd}.sb.bin`, `book/examples/sb/build/sample.sb.bin`.
- **Decoder & layouts (shared backbone):**
  - `book/api/decoder` (modern-heuristic decoder) with tag layouts from `book/graph/mappings/tag_layouts/tag_layouts.json` (`status: ok` from `tag-layout-decode`).
  - Segment-aware slicing and header parsing from `book/graph/concepts/validation/profile_ingestion.py`.
- **Related experiments:**
  - `field2-filters` – `field2` inventories and unknown/high clusters.
  - `tag-layout-decode` – canonical `tag_layouts.json`.
  - `anchor-filter-map` – `anchor_filter_map.json` (anchors ↔ Filter IDs).

The scope here is **structural**: we do not run runtime probes; we map compiled profiles and anchors into a structured view that other experiments and mappings consume.

## Deliverables / outcomes

- A probe matrix of SBPL profiles in `sb/` (`v0`–`v8`) that exercise file, mach, network, and iokit filters (and combos) with distinct anchors.
- Structural inventories under `out/`:
  - `analysis.json` – per‑profile op counts, node counts, and `field2` histograms (with filter‑name mapping) plus literal samples.
  - `tag_inventory.json` and `tag_layout_hypotheses.json` – stride‑based tag counts and early layout hypotheses, now superseded for covered tags by `book/graph/mappings/tag_layouts/tag_layouts.json`.
  - `literal_scan.json` and `tag_bytes.json` – scratch views of node bytes vs literal offsets.
  - `anchor_hits.json` – **anchor → node indices → `field2` values** across probes and system profiles, built on the shared decoder and tag layouts.
- Evidence that:
  - probe profiles remain structurally dominated by **generic path/name filters** in `field2`, and
  - for a small set of anchors we can reliably bind anchors → nodes → `field2` and cross‑check those bindings against system profiles and `anchor_filter_map.json`.

## Plan & execution log (summary)

### 1. Probe matrix and initial `field2` census

- Designed a small probe matrix under `sb/`:
  - File‑only: `v0_file_require_all`, `v1_file_require_any`, `v2_file_three_filters_any`.
  - Mach/network/iokit: `v3_mach_global_local`, `v4_network_socket_require_all`, `v5_iokit_class_property`.
  - Mixed: `v6_file_mach_combo`, `v7_file_network_combo`, `v8_all_combo`.
- Compiled via `libsandbox` and decoded with early heuristics; `field2` histograms already showed **generic filter dominance**:
  - File probes: mostly `file-mode` (3), `ipc-posix-name` (4), `global-name` (5), `local-name` (6).
  - Mach probes: `global-name` (5), `local-name` (6).
  - Network probes: `remote` (8), `local` (7), plus a single unknown 2560.
  - Mixed probes re‑used the same low IDs; `v8_all_combo` initially failed slicing (node_count=0).

### 2. Decoder and slicing: recovering nodes and tags

- Added segment‑aware slicing in `profile_ingestion.py` and re‑used it in the decoder so that complex profiles (`v8_all_combo`) now yield node chunks even when naive literal-start detection fails.
- Built coarse tag inventories in `out/tag_inventory.json` using `tag_inventory.py`:
  - Historical note: earlier stride‑sweep work treated 12/16 as “stable”; the current decoder+canonical tag layouts now treat node records as 8‑byte fixed‑stride for this world baseline.
  - Used `tag_layout_hypotheses.py` + `out/tag_layout_hypotheses.json` to sketch early layout hypotheses for tags 0,5,6,17,26,27 (edges vs payload fields) as a **sanity check**, not a final map.
- These exploratory layouts were captured in `out/tag_layout_assumptions.json` and later **superseded** for tags that appear in `book/graph/mappings/tag_layouts/tag_layouts.json` (0,1,3,5,7,8,17,26,27,166).

### 3. Tag-aware decoding under the canonical layouts

- `book/api/decoder` now merges:
  - built‑in defaults for tags 5/6, and
  - external layouts from `book/graph/mappings/tag_layouts/tag_layouts.json` (preferred when present),
  with a host‑scoped node framing selector that prefers an 8‑byte record stride based on op‑table alignment witnesses.
- With this in place:
  - Canonical tags are decoded with **record_size=8, fields[0..1] as edges, field[2] as payload**.
  - High system tags 26 and 27 in `sys:bsd` are no longer structurally “blocked”; their records are parsed with the same edge/payload split used by downstream experiments and mappings.
- `analysis.json` was regenerated via `analyze_profiles.py` under this decoder:
  - Probes still show generic filter dominance in `field2` (see Findings).
  - System profiles reflect richer filters and high/unknown values, matching `field2-filters` inventories.

### 4. Anchor‑aware mapping: anchors → nodes → `field2`

- Introduced `anchor_map.json` (per‑profile anchor strings) and `anchor_scan.py`, then:
  - Decoded each profile via `book/api/decoder.decode_profile_dict`.
  - Used `profile_ingestion` to slice node and literal sections.
  - Matched anchors to literals (including prefixed forms like `Ftmp/foo`) via:
    - `literal_strings_with_offsets` from the decoder, and
    - byte‑level scans of the literal pool.
  - Located node indices via:
    - `literal_refs` attached to each decoded node (preferred), and
    - residual byte‑level scans of node records when no refs were present.
- The result, `out/anchor_hits.json`, now records for each profile:
  - `op_count`, `node_count`,
  - per‑anchor `offsets` in the literal pool,
  - `node_indices` that reference those literals, and
  - `field2_values`/`field2_names` at those nodes.

### 5. Cross‑experiment integration

  - `anchor-filter-map` consumes `anchor_hits.json` and `field2-filters` inventories to produce `book/graph/mappings/anchors/anchor_filter_map.json`:
    - Some anchors are now **pinned** to specific filters (e.g., `/var/log` → `ipc-posix-name`, `idVendor` → `local-name`, `preferences/logging` → `global-name`) with `status: partial`.
  - Others remain **blocked** where `field2` evidence is mixed (e.g., `com.apple.cfprefsd.agent`, `flow-divert`, `IOUSBHostInterface`).
- `tag-layout-decode` used canonical system profiles and literal‑bearing nodes to publish `tag_layouts.json`, which this experiment now treats as the authoritative per‑tag layout map. The older `tag_layout_assumptions.json` in this directory is best read as historical scaffolding rather than a live layout source.

## Findings

### Generic path/name dominance in probes

From `out/analysis.json`:

- File‑focused probes:
  - `v0_file_require_all`: `field2` dominated by `ipc-posix-name` (4) and `file-mode` (3).
  - `v1_file_require_any` and `v2_file_three_filters_any`: mixtures of `global-name` (5), `local-name` (6), `ipc-posix-name` (4), and a single `path` (0) value where anchors bind.
- Mach/iokit probes:
  - `v3_mach_global_local` and `v5_iokit_class_property`: primarily `local-name` (6) and `global-name` (5) with a single `path` (0).
- Network probes:
  - `v4_network_socket_require_all` and `v7_file_network_combo`: `remote` (8) and `local` (7) dominate, with a few `ipc-posix-name` (4) and `global-name` (5) nodes plus one unmapped 2560 and one `xattr` (2).
- Mixed `v6_file_mach_combo`: `global-name` (5) and `ipc-posix-name` (4) only.

These patterns confirm the original observation: for small probe profiles, **shared scaffolding filters** (paths, names, remote/local) dominate `field2`, and filter‑specific IDs are hard to isolate structurally.

### High‑tag layouts in system profiles

Under the canonical tag layouts (`book/graph/mappings/tag_layouts/tag_layouts.json`) and `analysis.json`:

- `sys:bsd`:
  - Tags 26 and 27 are decoded with `record_size=8`, two edge fields, and `field2` as the payload slot.
  - Under the stride=8 framing, `sys:bsd`’s `field2` payloads align fully with the host filter vocabulary (no out-of-vocab payloads in the canonical `bsd` profile); the earlier “bsd tail/high” set was a decode-framing artifact from the stride=12 approximation.
- `sys:airlock`:
  - `airlock` still carries out-of-vocab `field2` payloads in some tags; the current unknown census is intentionally scoped to tags with `u16_role=filter_vocab_id` (see `book/experiments/field2-filters/out/unknown_nodes.json`).
  - The `app-sandbox.*` anchors appear in the literal pool; `anchor_hits.json` shows limited node bindings (field2 empty at the node index chosen by current heuristics), so semantic interpretation remains **blocked**.
- `sys:sample`:
  - Shows a mix of `remote` (8), `local` (7), `file-mode` (3), `mount-relative-path` (1), `path` (0), plus a small set of out-of-vocab payloads (notably 256/1281/3584), matching the `field2-filters` story for `sample`.
  - The `/etc/hosts` anchor binds to nodes whose `field2` set includes {`mount-relative-path` (1), `path` (0), 3584, `local` (7)}; this mixture is reflected in `anchor_filter_map.json` and kept `status: partial`.

Together, these observations show that the **structural layout of high tags (including 26/27/166) is now understood** for this world, but the semantics of several high `field2` values remain unmapped or fragile. This experiment provides the structural evidence; `field2-filters` and future work must refine the semantic interpretation.

### Anchor → node → `field2` pathways

Using `out/anchor_hits.json`:

- **File anchors**
  - `/tmp/foo`:
    - `probe:v1_file_require_any`: node indices [16,22,30] with `field2` = {`global-name` (5), `local-name` (6), `path` (0)}.
    - `probe:v2_file_three_filters_any`: nodes [16,23] with `field2` = {`ipc-posix-name` (4), `ipc-posix-name` (4)}.
    - Mapping: the `/tmp/foo` entry in `book/graph/mappings/anchors/anchor_filter_map.json` pins this anchor to `filter_id = 0` (`path` in `book/graph/mappings/vocab/filters.json`) with `status: partial` and records the observed `field2_values` {0,4,5,6}.
  - `/etc/hosts`:
    - `probe:v1_file_require_any`: node 15 with `field2` = `local-name` (6).
    - `probe:v2_file_three_filters_any`: node 15 with `field2` = `global-name` (5).
    - `sys:sample`: nodes [15,22,30,31] with `field2` = {`mount-relative-path` (1), `path` (0), 3584, `local` (7)}.
    - Mapping: the `/etc/hosts` entry in `anchor_filter_map.json` also pins this anchor to `filter_id = 0` (`path`) with `status: partial` and a recorded `field2_values` set {0,1,5,6,7,3584}.
- **Network/iokit/mach anchors**
  - `flow-divert`:
    - `probe:v4_network_socket_require_all` / `probe:v7_file_network_combo`: `field2` at bound nodes = {`local` (7), 2560, `xattr` (2)}.
    - Mapping: the `flow-divert` entry in `anchor_filter_map.json` is explicitly `status: blocked` with candidates `{local, xattr}` and `field2_values` {2,7,2560}; do not treat this as a resolved mapping.
  - `com.apple.cfprefsd.agent`:
    - `probe:v3_mach_global_local`: node indices [16,22,30] with `field2` = {`global-name` (5), `local-name` (6), `path` (0)}.
    - `probe:v6_file_mach_combo`: nodes [16,23] with `field2` = {`ipc-posix-name` (4), `ipc-posix-name` (4)}.
    - Mapping: `anchor_filter_map.json` marks this anchor `status: blocked` with candidates `{global-name, local-name, ipc-posix-name, path}` and `field2_values` {0,4,5,6}.
  - `IOUSBHostInterface` and `idVendor`:
    - `IOUSBHostInterface`: nodes [16,22,30] with `field2` = {`global-name` (5), `local-name` (6), `path` (0)}; mapping: `status: blocked` in `anchor_filter_map.json` with candidates `{global-name, local-name, path}`.
    - `idVendor`: node 15 with `field2` = `local-name` (6); mapping: pinned in `anchor_filter_map.json` to `filter_id = 6` (`local-name` in `filters.json`) with `status: partial` and `field2_values` {6}.
- **System anchor**
  - `preferences/logging` in `sys:bsd`: node 12 with `field2` = `global-name` (5); mapping: the `preferences/logging` entry in `anchor_filter_map.json` pins this anchor to `filter_id = 5` (`global-name`) with `status: partial` and `field2_values` {5}.

These pathways show how this experiment contributes **concrete, profile‑local evidence** to anchor → Filter mappings, while honestly preserving ambiguity where `field2` values are mixed or unknown.

## Anchor status summary for this world

This table summarizes the anchors that this experiment **actively touches** (i.e. have entries in `out/anchor_hits.json`) and how they are represented in `book/graph/mappings/anchors/anchor_filter_map.json` for this world:

- **Solid (structural)** – anchor has a pinned `filter_id` in `anchor_filter_map.json`, and the new guardrail (`test_anchor_filter_alignment.py`) confirms that `field2_values` observed in `anchor_hits.json` include that `filter_id` and are fully listed in the mapping’s `field2_values`. These anchors have a reliable **structural** anchor → Filter story on this host, even though semantics remain partial.
- **Blocked** – anchor is marked `status: "blocked"` in `anchor_filter_map.json` (no `filter_id`), even if candidates are listed. These are deliberately unresolved; do not treat them as mapped.

| anchor                    | status                         | filter_id | filter_name      | field2_values (structural)      |
|---------------------------|--------------------------------|-----------|------------------|---------------------------------|
| `/tmp/foo`               | solid (structural, partial)   | 0         | path             | 0, 4, 5, 6                      |
| `/etc/hosts`             | solid (structural, partial)   | 0         | path             | 0, 1, 5, 6, 7, 3584             |
| `/var/log`               | solid (structural, partial)   | 4         | ipc-posix-name   | 4                               |
| `idVendor`               | solid (structural, partial)   | 6         | local-name       | 6                               |
| `preferences/logging`    | solid (structural, partial)   | 5         | global-name      | 5                               |
| `com.apple.cfprefsd.agent` | blocked (candidates only)     | —         | —                | 0, 4, 5, 6                      |
| `flow-divert`            | blocked (candidates only)     | —         | —                | 2, 7, 2560                      |
| `IOUSBHostInterface`     | blocked (candidates only)     | —         | —                | 0, 5, 6                         |

**How to use this table:**

- When you need a **concrete, defensible anchor → Filter story** for this world, prefer anchors in the “solid (structural, partial)” rows; their structural mapping is backed by both `anchor_hits.json` and the guardrail.
- Treat “blocked” rows as deliberately unsolved; they record structural evidence (`field2_values` and candidates) but do **not** constitute a mapping. Do not upgrade them based on this experiment alone.

## Running and refreshing this experiment

- **Expected working directory:** repository root (`SANDBOX_LORE`), i.e. the directory that contains `book/`, `substrate/`, and `status/`.
- **Regenerating local outputs:**
  - `python3 book/experiments/probe-op-structure/analyze_profiles.py`
  - `python3 book/experiments/probe-op-structure/anchor_scan.py`
- Both scripts compute `ROOT = Path(__file__).resolve().parents[3]` and import `book.api.decoder`, so they expect to run from anywhere with the repo root on `sys.path` (running them from the repo root is the simplest path).
- Outputs are current with the trimmed node-region remainder contract and tag-layout mapping (meta tags 2/3 and payload-bearing tag10). Rerun after decoder/tag-layout changes to keep `analysis.json` and `anchor_hits.json` aligned.
- **Running tests / guardrails:**
  - The unified harness is `make -C book test`, which runs `python3 ci.py` and, in turn, `python -m book.tests.run_all`.
  - On this host, the CI harness currently calls:
    - `/opt/homebrew/opt/python@3.14/bin/python3.14 -m book.tests.run_all`
  - If you see `pytest is required to import tests (install it in your venv)`, that is an **environmental error** (pytest missing for Python 3.14), not a failure of this experiment’s logic. Install pytest into the interpreter used by the harness, then rerun.

## Evidence & artifacts

- **Probe assets**
  - SBPL sources and compiled blobs: `book/experiments/probe-op-structure/sb/` and `sb/build/`.
  - Anchor map: `book/experiments/probe-op-structure/anchor_map.json`.
- **Local outputs (`out/`)**
  - `analysis.json` – per‑profile `field2` histograms and literal samples.
  - `tag_inventory.json`, `tag_layout_hypotheses.json`, `tag_bytes.json` – stride‑based tag inventories and exploratory layout notes.
  - `tag_layout_assumptions.json` – early per‑tag layout hypotheses (including tags 5,6,26,27); now historical scaffolding, not a live layout source when `tag_layouts.json` is present.
  - `literal_scan.json` – anchor‑offset hits in node bytes (pre‑decoder literal_refs).
  - `anchor_hits.json` – anchor → node indices → `field2` values and names, regenerated via `anchor_scan.py` under the current decoder and tag layouts.
  - `out/README.md` – short description of these artifacts and their role.
- **Shared mappings that consume this experiment**
  - Tag layouts: `book/graph/mappings/tag_layouts/tag_layouts.json` (from `tag-layout-decode`, `status: ok`).
  - Anchor map: `book/graph/mappings/anchors/anchor_filter_map.json` (from `anchor-filter-map`, anchors marked `partial` or `blocked`).
  - `field2` vocab and inventories: `book/graph/mappings/vocab/filters.json` plus `book/experiments/field2-filters/out/field2_inventory.json` and `unknown_nodes.json`.

## Guardrails and invariants

This experiment’s structural outputs participate in two core guardrails:

- **Mapping guardrail (`book/tests/test_mappings_guardrail.py`):**
  - Asserts that the canonical tag-layout mapping (`book/graph/mappings/tag_layouts/tag_layouts.json`) exists, is `status: ok`, and is pinned to this world baseline, alongside other core mappings.
- **Anchor alignment guardrail (`book/tests/test_anchor_filter_alignment.py`):**
  - Treats `book/graph/mappings/anchors/anchor_filter_map.json` as the curated anchor → Filter map, and `out/anchor_hits.json` as this experiment’s anchor → node → `field2` evidence.
  - For **each mapped, non-blocked anchor** (entry with a `filter_id`, `sources`, and `status` not equal to `"blocked"`), it enforces three checks:
    - **Witness required:** there must be at least one observation of that anchor in `anchor_hits.json` under the listed `sources` (i.e. `observed` is non‑empty).
    - **Pinned filter present:** the pinned `filter_id` must appear among the observed `field2_values` for that anchor in `anchor_hits.json`.
    - **No unrecorded values:** every observed `field2` value for that anchor must be listed in the mapping’s `field2_values` array.

### What failing the guardrail means

- **Mapped anchor with no hits:** the anchor has been listed in `anchor_filter_map.json` with `sources`, but the experiment no longer produces corresponding entries in `anchor_hits.json`. Fix by re-running/repairing the probes or adjusting `sources` to match the actual profiles.
- **Pinned filter not observed:** `anchor_filter_map.json` claims that anchor A is pinned to Filter ID F, but `anchor_hits.json` never sees F in `field2_values` for A. Fix by either correcting the mapping (if F was wrong) or revisiting the experiment (if probes were insufficient).
- **New observed field2 not in `field2_values`:** the experiment has observed new `field2` values for an anchor that the mapping does not list. Fix by updating the mapping’s `field2_values` set (and, if necessary, its `status`) or by refining the experiment if the new value is an artifact.

These guardrails make `anchor_filter_map.json` and `out/anchor_hits.json` move together: any change to one side that is not backed by the other will trip tests and demand an explicit fix.

## Blockers / risks

- **Literal/regex operands still partial.** Even with canonical tag layouts and `literal_refs`, literal/regex operands are only partially surfaced; for many tags and profiles, anchors remain bound through heuristic byte‑scans rather than explicit operands.
- **Generic filters mask specifics.** In the probe matrix, shared scaffolding filters (`path`, `global-name`, `local-name`, `ipc-posix-name`, `remote`, `local`) dominate `field2`, making it hard to isolate filter‑specific payloads without more surgical probes.
- **High `field2` values unmapped.** High and sentinel values (e.g., 16660 in `sys:bsd`, 165/166/10752 in `sys:airlock`, 2560 in `flow-divert`, 3584 in `sample`) are well‑bounded structurally but remain semantically unmapped or only weakly constrained by current experiments. Claims about their meaning stay **partial/blocked**.
- **Heuristic anchor matching.** `_matches_anchor` and byte‑level scans can mis‑associate anchors that share substrings or prefixes; ambiguous cases are explicitly marked as such in `anchor_filter_map.json`, but agents should treat those mappings as **under exploration**.

## How this experiment fits into the larger picture

- **Tag-layout decode (`book/experiments/tag-layout-decode/`):**
  - Defines the canonical tag layouts in `book/graph/mappings/tag_layouts/tag_layouts.json`. This experiment consumes those layouts via `book/api/decoder` to interpret node tags and payload positions.
- **Field2-filters (`book/experiments/field2-filters/`):**
  - Enumerates `field2` usage across canonical system profiles and selected probes, and captures unknown/high values in `field2_inventory.json` and `unknown_nodes.json`. This experiment provides **anchor-aware structure** (`anchor_hits.json`) that helps tie specific anchors to those `field2` values.
- **Anchor-filter map (`book/experiments/anchor-filter-map/`):**
  - Uses `anchor_hits.json`, `field2` inventories, and the Filter vocabulary to synthesize `book/graph/mappings/anchors/anchor_filter_map.json`. The new guardrail (`test_anchor_filter_alignment.py`) ensures that the curated map remains aligned with this experiment’s structural witnesses.

## Limitations and non-claims

- We **do not** currently know the full semantic meaning of high `field2` values such as 16660 (`sys:bsd`), 165/166/10752 (`sys:airlock`), 2560 (`flow-divert`), or 3584 (`sys:sample`). They should be treated as opaque IDs with known tag/graph context only, as recorded in `book/experiments/field2-filters/out/field2_inventory.json` and `unknown_nodes.json`.
- Anchors marked `status: "blocked"` in `book/graph/mappings/anchors/anchor_filter_map.json` (for example `com.apple.cfprefsd.agent`, `flow-divert`, `IOUSBHostInterface`) are intentionally left unmapped; this experiment does **not** provide a resolved Filter mapping for them.
- Literal/regex operands are **not fully decoded** for all tags and profiles; node `literal_refs` and byte-level scans are helpful hints, but they are not sufficient to reconstruct full path or regex semantics. Do not infer detailed path patterns from this experiment alone.
- Generic scaffolding filters (`path`, `global-name`, `local-name`, `ipc-posix-name`, `remote`, `local`) dominate many probe graphs; this experiment does **not** claim to separate all fine-grained filters from this scaffolding.
- This experiment is **structural only**: it does not make or validate runtime allow/deny claims. Any runtime semantics for operations and filters must come from the runtime experiments (`runtime-checks`, `runtime-adversarial`, `sbpl-graph-runtime`) and their mappings, not from `probe-op-structure` alone.

## Status & next steps

- **Status for this experiment:** **partial**.
  - Structural backbone (probe matrix, decoder integration, tag layouts, anchor → node → `field2` wiring, and guardrails) is in good shape and used by other experiments and mappings.
  - Semantic claims about specific high `field2` values and some anchors remain tentative or blocked.

**Next steps (when revisiting this area):**

1. **Design more discriminating probes per filter family.**
   - For each ambiguous anchor (e.g., `com.apple.cfprefsd.agent`, `flow-divert`, `IOUSBHostInterface`), design SBPL variants that hold paths/names fixed while varying only the target filter or metafilter, to see how `field2` and tag usage change.
2. **Exploit canonical tag layouts more directly.**
   - Use `book/graph/mappings/tag_layouts/tag_layouts.json` to focus on nodes with tags 26/27/166 that are reachable from relevant ops and anchors, and cross‑reference their `field2` payloads with `book/experiments/field2-filters/out/unknown_nodes.json`.
3. **Tighten anchor mapping where evidence converges.**
   - When an anchor’s `field2` values converge across probes and system profiles (as with `/var/log`, `idVendor`, `preferences/logging`), consider upgrading its status in `anchor_filter_map.json` from `partial` to `ok`, backed by explicit references to `out/anchor_hits.json` and `field2` IR.
4. **Keep this experiment as a reusable structural fixture.**
   - Treat `analysis.json`, `anchor_hits.json`, and the probe SBPL as a stable, host‑bound structural fixture that other experiments and mappings can rely on when reasoning about `field2` and literal/tag structure on this world.

At this point, the core goal of this experiment—**to provide a structured, anchor‑aware view of `field2` usage across probes and system profiles**—is met for this world, even though several semantics remain deliberately marked as **partial** or **blocked** pending future work.
