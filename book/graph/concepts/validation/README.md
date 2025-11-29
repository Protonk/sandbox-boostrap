# Validation Harness Skeleton

This directory holds the code/metadata for validating the concept clusters against the `book/examples/` labs. The goal is to keep all harness code here and let the examples remain focused on their domain probes.

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
