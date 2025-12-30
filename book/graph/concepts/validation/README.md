# Validation Harness Skeleton

This directory holds the code/metadata for validating the concept clusters against the `book/examples/` labs. The goal is to keep all harness code here and let the examples remain focused on their domain probes.

Current status: sandbox-exec-based semantic and lifecycle runs are deferred while the harness is being repaired; static ingestion and vocab mapping are current, and the CARTON bundle (manifest + relationships/views/contracts, see `book/integration/carton/bundle/CARTON.json`) is the frozen IR/mapping web this validation layer feeds.

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
- Describe a job: `python -m book.graph.concepts.validation --describe <job_id>`
Jobs are registered in `registry.py`; add new ones next to the decode/ingestion logic they exercise. Notable jobs include vocab extraction, runtime-checks normalization, system-profile digests, field2 probes, fixtures/meta, and `experiment:golden-corpus` (replays decoder/profile against the golden-corpus manifest, including static-only platform profiles such as `platform_airlock`, to keep structural signals aligned with on-disk blobs).

Status schema (applies to `validation_status.json` and per-experiment status files):
- `job_id` (string), `status` (`ok|partial|brittle|blocked|skipped`), `tier` (`bedrock|mapped|hypothesis`), `host` (object), `inputs` (list of paths), `outputs` (list of paths), `tags` (list of strings), optional `notes`, `metrics`, `hashes`, `change`.
- Meta check: `python -m book.graph.concepts.validation --tag meta` runs `validation:schema-check` to assert status files follow this schema.
- If a job downgrades from `ok` to `partial`/`brittle`, note it in the job’s README/Report and scan for mappings that consume it; regenerate or explicitly tolerate the downgrade rather than silently continuing to trust `ok`.

Smoke tag:
- `python -m book.graph.concepts.validation --tag smoke` runs the core fast jobs (vocab:sonoma-14.4.1 + experiment:field2 + experiment:runtime-checks) as a default pre-promotion gate. `tag:golden` marks canonical jobs.

Promotion contract:
- Mapping generators must: (1) run the validation driver for relevant tags/IDs, (2) refuse to proceed on non-`ok` jobs, (3) read normalized validation IR only (not raw experiment out/), and (4) carry host/provenance (`host`, `source_jobs`) into outputs. See `book/graph/mappings/run_promotion.py` and `generate_runtime_signatures.py` / `generate_digests_from_ir.py` for the pattern.
- CARTON: the frozen IR/mapping bundle for Sonoma 14.4.1 lives under `book/integration/carton/bundle/` with its manifest at `book/integration/carton/bundle/CARTON.json`. After rerunning validation + mapping generators, refresh CARTON via `python -m book.integration.carton.tools.update` to rebuild relationships/views/contracts and the manifest. Schema checks assert CARTON and mapping provenance. CARTON is what the textbook and CI read; this validation directory is where you extend or regenerate the IR that feeds it.

Keep Swift-side validation non-fatal: extend the report rather than blocking generation when checks fail.

## Files

- `tasks.py` – declarative mapping of validation tasks to examples, inputs, and expected artifacts. Used as the source of truth for which examples exercise which clusters.
- (future) `out/` – drop-in location for captured evidence (JSON logs, parsed headers, vocab tables) keyed by cluster/run/OS version.
- Decoder lives under `book/api/profile/decoder/` (Python); import `book.api.profile.decoder` (or `from book.api.profile import decoder`) in validation tooling.

## Usage model (planned)

1. Use `tasks.py` to enumerate the validation tasks for a cluster.
2. For Static-Format tasks, compile the SBPL inputs using `python -m book.api.profile compile …` (see `tasks.py`) and feed the resulting `.sb.bin` blobs through the shared ingestion layer to emit JSON summaries under `out/static/`.
3. For Semantic Graph tasks, run the microprofiles/probes (e.g., `metafilter-tests`, `sbpl-params`, `network-filters`) and capture structured outcomes under `out/semantic/`, making sure to annotate TCC/SIP involvement when observed.
4. For Vocabulary tasks, extract operation/filter maps from compiled blobs (from Static-Format) and from runtime logs (from Semantic Graph), then normalize into versioned tables under `book/graph/mappings/vocab/` (a shared, stable location). Stable op-table artifacts live under `book/graph/mappings/op_table/`.
5. For Runtime Lifecycle tasks, run the scenario probes (`entitlements-evolution`, `platform-policy-checks`, `containers-and-redirects`, `extensions-dynamic`, `libsandcall` apply attempts) and capture label/entitlement/container/extension evidence under `out/lifecycle/`.

All scripts and automation that support these steps should live in this directory; example code remains under `book/examples/`.
