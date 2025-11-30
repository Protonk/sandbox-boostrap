# SBPL ↔ Graph ↔ Runtime – Research Report

## Purpose

Demonstrate round-trip alignment between SBPL source, compiled graph structure, and runtime allow/deny outcomes on a small set of canonical profiles. Provide concrete triples that witness semantic concepts and tie into static/vocab views.

## Baseline

- Host: TDB (record OS/build/SIP when runs are performed).
- Tooling: reuse `profile_ingestion.py` for decoding; use a lightweight probe harness (sandbox-exec or local runner) for runtime checks.
- Profiles: allow-all/deny-all, deny-except, filtered allow, metafilter, parameterized path.

## Status

- Profiles authored: allow_all, deny_all, deny_except_tmp, metafilter_any (param_path pending param injection). Compiled to binaries with `sbsnarf.py` (absolute paths) and decoded via `profile_ingestion.py`; see `out/ingested.json` for header/section summaries (modern-heuristic).
- Runtime probes: now using `book/api/SBPL-wrapper/wrapper --sbpl` plus a slim file-probe binary (`book/api/file_probe/file_probe`). `allow_all` behaves as expected. Strict `(deny default)` profiles (`deny_all`, `deny_except_tmp`, `metafilter_any`) still kill the probe with exit -6 even after adding `process-exec*`, `process-fork`, system path reads, and /tmp metadata allowances. Conclusion: micro-additions aren’t surfacing allow outcomes; to observe allow branches we need to relax defaults (allow default + explicit denies), which we haven’t yet applied here. System-style triples could include `bsd` (SBPL/compiled blob applies here); `airlock` is expected-fail locally.
