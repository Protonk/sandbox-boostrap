Validation artifacts (Sonoma 14.4.1 / 23E224, arm64, SIP on)

Current status:
- Static-format ingestion: ok (sample/system profiles, mappings pointers).
- Vocabulary: ok (ops.json 196, filters.json 93).
- Semantic graph: partial (wrapper/reader runtime probes: allow_all, metafilter_any, bucket4 ok; bucket5 partial; platform blobs skipped).
- Lifecycle/extension: partial (entitlements-evolution runnable; extensions/containers/platform probes not rerun).

See `index.json` for a machine-readable summary of artifacts and statuses.
