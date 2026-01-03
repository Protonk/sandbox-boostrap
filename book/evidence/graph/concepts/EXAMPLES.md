# Witnesses and Concept Clusters

This file maps concept clusters to the active witness artifacts and harnesses in this repo, and shows how their outputs flow into shared validation and mapping layers.

It is not a step-by-step runbook; use the nearest README in each tool or experiment directory for execution details.

## Cluster ↔ witness map (quick view)

- **Static-Format** – compiled profile structure, headers, op tables, regex/literal tables, profile format variants.  
  Witnesses: SBPL corpus samples + system profile fixtures + parameterization validation outputs.

- **Semantic Graph and Evaluation** – operations, filters, metafilters, decisions, runtime behavior.  
  Witnesses: runtime-checks experiment bundles and the golden-triple harness (runtime expectations + traces).

- **Vocabulary and Mapping** – operation/filter vocab maps and name↔ID alignment.  
  Witnesses: dyld-derived vocab tables, op-table alignment outputs, and normalization runs that cross-check runtime usage.

- **Runtime Lifecycle and Extension** – profile layers, policy stack order, entitlements, extensions, containers, adjacent controls.  
  Witnesses: lifecycle probes via `book.api.lifecycle`, normalized lifecycle traces, and runtime lifecycle mappings.

The rest of this file explains these relationships cluster-by-cluster.

---

## Static-Format witnesses

Static-format witnesses are built from SBPL specimens and compiled system profiles, then decoded by shared ingestion tooling.

- **SBPL corpus sample** (`book/tools/sbpl/corpus/baseline/sample.sb`)
  - Compile with `python -m book.api.profile compile`.
  - Outputs land in `book/evidence/graph/concepts/validation/fixtures/blobs/` and are summarized under `book/evidence/graph/concepts/validation/out/static/`.
  - Feeds system-profile digests and attestations under `book/integration/carton/bundle/relationships/mappings/system_profiles/`.

- **System profile fixtures** (`book/evidence/graph/concepts/validation/fixtures/blobs/{airlock,bsd}.sb.bin`)
  - Compiled from `/System/Library/Sandbox/Profiles/*.sb` via `book.api.profile`.
  - Used for static checks, op-table alignment, and tag-layout validation.

- **Parameterization validation** (`book/evidence/graph/concepts/validation/out/{sbpl_parameterization,sbpl_param_value_matrix}/status.json`)
  - Captures compile-time behavior of `(param ...)` specimens for this host.

Legacy decision-tree formats are not part of the active harness; if a legacy blob is available, document it explicitly and keep its outputs clearly labeled.

---

## Semantic Graph and Evaluation witnesses

Semantic witnesses are driven by runtime bundles and golden-triple profiles rather than ad-hoc sandbox-exec probes.

- **Runtime-checks experiment** (`book/evidence/experiments/runtime-final-final/suites/runtime-checks/`)
  - Run via `python -m book.api.runtime run --plan ... --channel launchd_clean`.
  - Normalized outputs live at `book/evidence/graph/concepts/validation/out/experiments/runtime-checks/runtime_results.normalized.json`.
  - Feeds runtime expectations and trace mappings under `book/integration/carton/bundle/relationships/mappings/runtime/`.

- **Golden-triple harness** (`book/profiles/golden-triple/`)
  - Provides curated SBPL/compiled/runtime triples for allow_all, metafilter_any, bucket4, and bucket5 profiles.
  - Feeds `book/integration/carton/bundle/relationships/mappings/runtime/expectations.json` + `traces/*`.

Legacy sandbox-exec snapshots remain under `book/evidence/graph/concepts/validation/out/semantic/` for historical context, but they are not a current regeneration path.

---

## Vocabulary and Mapping witnesses

Vocabulary/mapping evidence is anchored in dyld extraction and op-table alignment, with runtime checks as a secondary cross-check.

- **Dyld-derived vocab**: `book/graph/mappings/vocab/generate_vocab_from_dyld.py` → `book/integration/carton/bundle/relationships/mappings/vocab/{ops.json,filters.json,attestations.json}`.
- **Op-table alignment**: `book/integration/carton/bundle/relationships/mappings/op_table/op_table_vocab_alignment.json`.
- **Runtime cross-check**: normalized runtime events from runtime-checks (see semantic section) can be mapped back to vocab IDs to flag unknowns.

---

## Runtime Lifecycle and Extension witnesses

Lifecycle witnesses come from host-bound probes and normalized lifecycle traces.

- **Lifecycle probes**: `book.api.lifecycle` CLI produces outputs under `book/evidence/graph/concepts/validation/out/lifecycle/`.
- **Lifecycle mappings**: `book/integration/carton/bundle/relationships/mappings/runtime/lifecycle.json` + `lifecycle_traces/*` for promoted scenarios.

---

## How to use this map

- Start from the cluster you care about and pick the smallest, most direct witness (fixtures or experiment bundles).
- Prefer evidence that is regenerable on this host and already feeds existing manifests under `book/integration/carton/bundle/relationships/mappings/` and `book/evidence/graph/concepts/validation/out/`.
- When adding a new witness, update the relevant manifest or status file rather than leaving evidence as a one-off log.
