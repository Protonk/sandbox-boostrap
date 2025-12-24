# Examples and Concept Clusters

This file explains how the examples under `book/examples/` serve as witnesses for the concept clusters in `CONCEPT_INVENTORY.md`, and how their outputs flow into the shared mapping/validation layer.

It is *not* a full “how to run” guide for each example (see `book/examples/AGENTS.md` for that), but a routing layer: when you pick an example, this tells you which concepts it supports and which manifests it feeds.

## Cluster ↔ example map (quick view)

- **Static-Format** – compiled profile structure, headers, operation tables, regex/literal tables, profile format variants.  
  Examples: `sb/`, `extract_sbs/`, `sbsnarf/`, `apple-scheme/`, `sbdis/`, `re2dot/`, `resnarf/`.

- **Semantic Graph and Evaluation** – operations, filters, metafilters, decisions, policy graph behavior.  
  Examples: `metafilter-tests/`, `sbpl-params/`, `network-filters/`, `mach-services/`, plus the golden-triple harness under `book/profiles/golden-triple/` (not in `book/examples/`).

- **Vocabulary and Mapping** – operation/filter vocab maps and name↔ID alignment.  
  Examples: `sb/`, `extract_sbs/`, `sbdis/`, `re2dot/`, `resnarf/` (all indirectly), with vocab extraction driven by `book/graph/mappings/vocab/generate_vocab_from_dyld.py` against `book/graph/mappings/dyld-libs/`.

- **Runtime Lifecycle and Extension** – profile layers, stack evaluation order, compiled profile source, containers, entitlements, extensions, adjacent controls.  
  Examples: `entitlements-evolution/`, `platform-policy-checks/`, `extensions-dynamic/`, `containers-and-redirects/`, `libsandcall/`.

The rest of this file explains these relationships cluster-by-cluster.

---

## Static-Format examples

Static-format examples produce compiled blobs and structural views that feed decoders, op-table experiments, tag layouts, and system-profile digests.

### `sb/`

- **Role:** Compile `sample.sb`, then parse the resulting modern graph-based blob via the shared ingestion layer.
- **Concept clusters:**  
  - **P:** Static-Format (Binary Profile Header, Operation Pointer Table, Profile Format Variant, PolicyGraph/Policy Node, Regex/Literal Table).  
  - **S:** Semantic Graph and Evaluation (PolicyGraph reconstruction), Vocabulary and Mapping (operation/filter IDs for the sample).
- **Feeds:**
  - `book/graph/concepts/validation/out/static/sample.sb.json`  
  - `book/graph/mappings/system_profiles/digests.json` (via curated inclusion as `sample`)  
  - `book/graph/mappings/system_profiles/{attestations.json,static_checks.json}` (sample entry).

### `extract_sbs/`

- **Role:** Compile selected system SBPL templates (e.g., `airlock.sb`, `bsd.sb`) with `libsandbox` and save `.sb.bin` blobs.
- **Concept clusters:**  
  - **P:** Static-Format (captured compiled profiles, format variants, system profile layers).  
  - **S:** Runtime Lifecycle and Extension (Compiled Profile Source: system templates).
- **Feeds:**
  - `book/graph/concepts/validation/fixtures/blobs/*.sb.bin` (canonical raw blobs).  
  - `validation/out/static/system_profiles.json` (ingestion summaries).  
  - `mappings/system_profiles/{digests.json,attestations.json,static_checks.json}`.

### `sbsnarf/`

- **Role:** Compile arbitrary SBPL text to `.sb.bin` via `sandbox_compile_file` (no apply).
- **Concept clusters:**  
  - **P:** Static-Format (compiled blob production across formats).  
  - **S:** Runtime Lifecycle and Extension (Compiled Profile Source for test/harness profiles).
- **Feeds:**
  - Custom blobs used by experiments; static ingestion outputs under `validation/out/static/` when wired via `validation/tasks.py`.

### `apple-scheme/`

- **Role:** C shim that calls `sandbox_compile_file` on `profiles/demo.sb` and writes `build/demo.sb.bin`.
- **Concept clusters:**  
  - **P:** Static-Format (Binary Profile Header, Profile Format Variant).  
  - **S:** Runtime Lifecycle and Extension (Policy Lifecycle Stage: SBPL compilation).
- **Feeds:**
  - Additional compiled blobs for decoder tests and format-variant sanity checks.

### `sbdis/`, `resnarf/`, `re2dot/`

- **Role:** Work with legacy decision-tree formats and AppleMatch regex tables:
  - `sbdis/` – disassemble legacy decision-tree profiles.  
  - `resnarf/` – extract AppleMatch regex blobs (`.re`).  
  - `re2dot/` – turn `.re` blobs into Graphviz `.dot`.
- **Concept clusters:**  
  - **P:** Static-Format (legacy node/regex layout, regex/literal table).  
  - **S:** Vocabulary and Mapping (linking regexes back to filters/operations).
- **Feeds:**
  - Legacy static ingestion outputs under `validation/out/static/`.  
  - Tag-layout work under `book/graph/mappings/tag_layouts/`; legacy regex tooling now lives in `book/examples/regex_tools/`.

---

## Semantic Graph and Evaluation examples

Semantic examples exercise operations, filters, and metafilters and (where possible) tie outcomes back to decoded graphs.

### `metafilter-tests/`

- **Role:** Use `sandbox-exec` with tiny SBPL profiles to demonstrate `require-any`, `require-all`, and `require-not` behavior on `file-read*`.
- **Concept clusters:**  
  - **P:** Semantic Graph and Evaluation (Metafilter, PolicyGraph shape).  
  - **S:** Static-Format (compiled graphs corresponding to SBPL metafilters).
- **Feeds:**
  - `validation/out/semantic/metafilter.jsonl` (legacy, `brittle`).  
  - Informal graph-shape comparisons when cross-checking decoder output; superseded by golden-triple metafilter profiles where possible.

### `sbpl-params/`

- **Role:** Demonstrate `(param "...")` templating and how parameter dictionaries change allowed paths under `sandbox-exec`.
- **Concept clusters:**  
  - **P:** Semantic Graph and Evaluation (SBPL Parameterization as part of semantic profile).  
  - **S:** Runtime Lifecycle and Extension (parameters supplied at compile/launch time).
- **Feeds:**
  - `validation/out/semantic/sbpl_params.jsonl` (legacy, `brittle`).

### `network-filters/`

- **Role:** Exercise TCP/UDP/UNIX sockets to map syscalls to `network-*` operations and filters (domain, type, remote/local addresses).
- **Concept clusters:**  
  - **P:** Semantic Graph and Evaluation (network operations and filters).  
  - **S:** Vocabulary and Mapping (socket-domain/type and network filter vocab).
- **Feeds:**
  - `validation/out/semantic/network.jsonl` (legacy, `brittle`).

### `mach-services/`

- **Role:** Register a bootstrap service and look it up alongside selected system services to show how `mach-lookup` and `(global-name ...)` filters behave.
- **Concept clusters:**  
  - **P:** Semantic Graph and Evaluation (`mach-lookup` operation, `global-name` filters).  
  - **S:** Vocabulary and Mapping (service-name/global-name vocab entries).
- **Feeds:**
  - `validation/out/semantic/mach_services.jsonl` (legacy, `brittle`).

### Golden-triple harness (outside `book/examples/`)

- **Location:** `book/profiles/golden-triple/` + `book/api/runtime_tools/`.  
- **Role:** Provide “golden” SBPL/graph/runtime triples (e.g., `allow_all`, `metafilter_any`, bucket4/bucket5 profiles) used for semantic validation.  
- **Feeds:** `mappings/runtime/expectations.json` + `mappings/runtime/traces/*` and `validation/out/semantic/runtime_results.json`.

---

## Vocabulary and Mapping examples

Vocabulary/mapping is mostly driven by dyld cache extraction and op-table experiments, but several examples supply the compiled blobs those experiments need.

### `sb/`, `extract_sbs/`, `sbdis/`, `re2dot/`, `resnarf/`

- **Role:** Produce or operate on compiled blobs whose op-table entries, filters, and regex/literal tables are used to align Operation/Filter vocab and op-tables.
- **Concept clusters:**  
  - **P:** Static-Format (as above).  
  - **S:** Vocabulary and Mapping (name↔ID, op-table alignment, regex usage).
- **Feeds:**
  - `mappings/vocab/{ops.json,filters.json}` (via dyld, not examples directly).  
  - `mappings/op_table/op_table_vocab_alignment.json` (op-table alignment for synthetic/sample profiles).  
  - `validation/out/vocab/*` (mirrored vocab tables and future runtime usage summaries).

Vocabulary extraction itself is driven by `book/graph/mappings/vocab/generate_vocab_from_dyld.py` plus `book/api/profile_tools/` (op-table tooling), not by a single `book/examples/` directory, but the examples above provide the concrete blobs needed to sanity check op-table/vocab alignment.

---

## Runtime Lifecycle and Extension examples

Lifecycle examples focus on profile provenance, entitlements, containers, extensions, and platform policy—everything around “which policies apply when?” instead of detailed graph semantics.

### `entitlements-evolution/`

- **Role:** Print signing identifier and entitlements for the running binary; meant to compare differently signed builds to see how entitlement-backed filters drive policy differences.
- **Concept clusters:**  
  - **P:** Runtime Lifecycle and Extension (entitlements as lifecycle inputs).  
  - **S:** Semantic Graph and Evaluation (entitlement-backed filters), Vocabulary and Mapping (entitlement keys and filter names).
- **Feeds:**
  - `validation/out/lifecycle/entitlements.json` (unsigned baseline; `partial`).  
  - `mappings/runtime/lifecycle.json` + `lifecycle_traces/entitlements-evolution.jsonl`.

### `platform-policy-checks/`

- **Role:** Probe sysctl, SIP-protected paths, and Mach services to surface platform/SIP denies that precede or override per-process SBPL.
- **Concept clusters:**  
  - **P:** Runtime Lifecycle and Extension (Profile Layer, Policy Stack Evaluation Order, adjacent controls).  
  - **S:** Semantic Graph and Evaluation (operations and filters hit by the probes).
- **Feeds:**
  - Lifecycle logs under `validation/out/lifecycle/` when wired into the harness; mapping-grade promotion still pending.

### `extensions-dynamic/`

- **Role:** Call `sandbox_extension_issue/consume/release`; expected to fail issuance without entitlements but illustrates the token workflow that feeds `(extension ...)` filters.
- **Concept clusters:**  
  - **P:** Runtime Lifecycle and Extension (Sandbox Extension, label state).  
  - **S:** Semantic Graph and Evaluation (extension filters and resulting decisions).
- **Feeds:**
  - `validation/out/lifecycle/extensions_dynamic.md` (notes on token issuance attempts).  
  - `mappings/runtime/lifecycle.json` + `lifecycle_traces/extensions-dynamic.jsonl` (scenario marked `blocked`).

### `containers-and-redirects/`

- **Role:** Walk `~/Library/Containers` and group containers, resolve symlinks, and show the canonical paths the sandbox evaluates.
- **Concept clusters:**  
  - **P:** Runtime Lifecycle and Extension (Container, filesystem view).  
  - **S:** Semantic Graph and Evaluation (path/vnode filters).
- **Feeds:**
  - Lifecycle logs under `validation/out/lifecycle/containers.json` when wired; mapping-grade promotion still pending.

### `libsandcall/`

- **Role:** Compile inline SBPL, print bytecode metadata, and attempt `sandbox_apply` (expected to `EPERM` without special entitlements).
- **Concept clusters:**  
  - **P:** Runtime Lifecycle and Extension (Policy Lifecycle Stage, applying profiles to labels).  
  - **S:** Static-Format (compiled blob structure), Semantic Graph and Evaluation (effects of applied profiles when they succeed).
- **Feeds:**
  - Lifecycle logs under `validation/out/lifecycle/` (apply attempts, error codes).  
  - Qualitative evidence for apply gates (`EPERM`) on this host.

---

## How to use this map

- When choosing an example to witness a concept, start with the **cluster** you care about and then pick from the examples listed above.
- For **static-format** and **vocab** work, favor `sb/` + `extract_sbs/` and look at the system profile manifests (`system_profiles/*`, `op_table/*`, `vocab/*`).
- For **semantic** work, favor the golden-triple harness (`book/profiles/golden-triple/`) and treat `metafilter-tests/`, `sbpl-params/`, `network-filters/`, and `mach-services/` as legacy/brittle probes.
- For **lifecycle** work, start with `entitlements-evolution/`, `extensions-dynamic/`, `libsandcall/`, and `containers-and-redirects/`, and use `mappings/runtime/lifecycle.json` as the high-level status view.

In all cases, aim to route new evidence into the existing manifests under `book/graph/mappings/` and `book/graph/concepts/validation/out/` so that the concept inventory, examples, and mapping layer stay tightly coupled. 
