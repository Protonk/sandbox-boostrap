# Golden Triple Profiles (provisional)

World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`

Purpose
- Canonical home for golden SBPL → PolicyGraph → runtime triples on this host.
- Golden criteria: simple SBPL, decoded graphs matching intent, static expectations (schema: provisional, `expectation_id` join key), runtime results aligned via `sandbox_init` from an unsandboxed caller, and (when promoted) linkage into the CARTON bundle (relationships/views/contracts; e.g., runtime signatures and system-profile coverage).

Profiles included
- `runtime:allow_all`
- `runtime:metafilter_any`
- `bucket4:v1_read`
- `runtime:param_deny_root_ok` (parameterized SBPL witness; host-bound)

Out of scope here
- Platform profiles (`sys:*`) — apply-gated on this host.
- Strict/apply-gate outliers (`bucket5:v11_read_subpath`, `param_path_concrete`, `param_path_bsd_bootstrap`) — remain in experiments until they align.

Artifacts written directly here
- SBPL sources and compiled blobs.
- Ingested summaries of compiled profiles.
- Static expectations (`static_expectations.json`, schema: provisional, with `expectation_id`).
- Runtime results (`runtime_results.json`) emitted by the harness against this directory.
- Manifest linking SBPL → blob → ingested → runtime.
