# Case study: bucket4_v1_read (SBPL → blob → graph → runtime)

Host: Sonoma 14.4.1 (23E224), CARTON bundle (manifest + relationships/views/contracts) tracked by `book/integration/carton/bundle/CARTON.json`.

- **SBPL source:** `book/profiles/golden-triple/bucket4_v1_read.sb` (`(deny default)` + `(allow file-read*)`).
- **Compiled blob:** `book/profiles/golden-triple/bucket4_v1_read.sb.bin` (also mirrored in runtime profiles under `book/experiments/runtime-final-final/suites/runtime-checks/out/runtime_profiles/v1_read.bucket4_v1_read.runtime.sb`).
- **Operations/filters:** uses vocab op `file-read*` (id 21 from `book/graph/mappings/vocab/ops.json`); no additional filters beyond the default op entrypoint.
- **Runtime behavior (from validation IR → mappings → CARTON relationships/views):**
  - `book/graph/concepts/validation/out/experiments/runtime-checks/runtime_results.normalized.json` records probes:
    - `read_/etc/hosts` → allow (stdout contains hosts file).
    - `read_/tmp/foo` → allow.
    - `write_/etc/hosts` → deny.
  - Summarized in `book/graph/mappings/runtime/runtime_signatures.json` under `signatures["bucket4:v1_read"]`.
- **Graph linkage:** op-table entrypoints decoded in `book/graph/mappings/runtime/runtime_signatures.json` come from the same blob; vocab IDs tie back to `ops.json`. Use `--describe experiment:runtime-checks` to see the IR job that feeds this mapping.
- **CARTON bundle review:** use `book/integration/carton/bundle/CARTON.json` plus the contract snapshots under `book/integration/carton/bundle/contracts/` and the relationships/views under `book/integration/carton/bundle/` to review frozen facts (probes, runtime blob path, op coverage) and any drift.

This profile is the exemplar for the validation→IR→mapping pipeline: SBPL source → compiled blob → validated runtime IR → frozen CARTON bundle (relationships/views/contracts).
