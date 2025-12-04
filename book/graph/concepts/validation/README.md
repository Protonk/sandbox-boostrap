# Validation Harness Skeleton

This directory holds the code/metadata for validating the concept clusters against the `book/examples/` labs. The goal is to keep all harness code here and let the examples remain focused on their domain probes.

Current status: sandbox-exec-based semantic and lifecycle runs are deferred while the harness is being repaired; static ingestion and vocab mapping are current.

Validation units (use these tags/IDs when adding jobs):
- `vocab:*` — libsandbox/dyld-cache vocab ingestion (ops/filters).
- `op-table:*` — op-table decoding/alignment runs.
- `runtime:*` — runtime trace decoding against expectations.
- `experiment:<name>` — validations whose inputs live under `book/experiments/<name>/out`.
- `graph:*` — consistency checks for artifacts under `book/graph/mappings/*`.

The Swift `book/graph` generator also writes a lightweight validation report here as `validation_report.json`, capturing schema/ID checks (e.g., concept IDs referenced by strategies and runtime expectations). Run it via:

```
cd book/graph
swift run
```

Python validation driver (single entrypoint):
- List jobs: `python -m book.graph.concepts.validation --list`
- Run everything: `python -m book.graph.concepts.validation --all`
- Run by tag/experiment: `python -m book.graph.concepts.validation --tag vocab` or `--experiment field2`
Jobs are registered in `registry.py`; add new ones next to the decode/ingestion logic they exercise.

Keep Swift-side validation non-fatal: extend the report rather than blocking generation when checks fail.

## Files

- `tasks.py` – declarative mapping of validation tasks to examples, inputs, and expected artifacts. Used as the source of truth for which examples exercise which clusters.
- (future) `out/` – drop-in location for captured evidence (JSON logs, parsed headers, vocab tables) keyed by cluster/run/OS version.
- Decoder lives at `book/api/decoder/` (Python); import `book.api.decoder` in validation tooling.

## Usage model (planned)

1. Use `tasks.py` to enumerate the validation tasks for a cluster.
2. For Static-Format tasks, run the listed example scripts (e.g., `sb/run-demo.sh`, `extract_sbs/run-demo.sh`) and feed the resulting `.sb.bin` blobs through the shared ingestion layer to emit JSON summaries under `out/static/`.
3. For Semantic Graph tasks, run the microprofiles/probes (e.g., `metafilter-tests`, `sbpl-params`, `network-filters`) and capture structured outcomes under `out/semantic/`, making sure to annotate TCC/SIP involvement when observed.
4. For Vocabulary tasks, extract operation/filter maps from compiled blobs (from Static-Format) and from runtime logs (from Semantic Graph), then normalize into versioned tables under `book/graph/mappings/vocab/` (a shared, stable location). Stable op-table artifacts live under `book/graph/mappings/op_table/`.
5. For Runtime Lifecycle tasks, run the scenario probes (`entitlements-evolution`, `platform-policy-checks`, `containers-and-redirects`, `extensions-dynamic`, `libsandcall` apply attempts) and capture label/entitlement/container/extension evidence under `out/lifecycle/`.

All scripts and automation that support these steps should live in this directory; example code remains under `book/examples/`.
