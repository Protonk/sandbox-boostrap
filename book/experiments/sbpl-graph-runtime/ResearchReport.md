# SBPL ↔ Graph ↔ Runtime – Research Report

## Purpose

Demonstrate round-trip alignment between SBPL source, compiled graph structure, and runtime allow/deny outcomes on a small set of canonical profiles. Provide concrete triples that witness semantic concepts and tie into static/vocab views.

## Baseline

- Host: TDB (record OS/build/SIP when runs are performed).
- Tooling: reuse `profile_ingestion.py` for decoding; use a lightweight probe harness (sandbox-exec or local runner) for runtime checks.
- Profiles: allow-all/deny-all, deny-except, filtered allow, metafilter, parameterized path.

## Status

- Profiles authored: allow_all, deny_all, deny_except_tmp, metafilter_any (param_path pending param injection). Compiled to binaries with `sbsnarf.py` (absolute paths) and decoded via `profile_ingestion.py`; see `out/ingested.json` for header/section summaries (modern-heuristic).
- Runtime probes: running via `sandbox_runner`/`sandbox_reader` on this host. `deny_all`/`deny_except_tmp` equivalents match expectations; `allow_all` mostly matches (OS perms deny `/etc/hosts` write). `metafilter_any` now passes (foo/bar allowed, other denied) after adding `/private/tmp` literals and using reader (no exec). Wrapper-based blob runs are available via the runtime-checks harness if we want to log probes directly against compiled blobs.
