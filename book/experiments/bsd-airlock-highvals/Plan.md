# Plan

- Establish baseline probes for the two clusters:
  - `bsd`: tag-26 highs (174/170/115/109) and tag-0 tail (16660) – try right-name / preference-domain / mac-policy-name mixes and literal-bearing rules inspired by bsd profile contents.
  - `airlock`: highs 165/166/10752/sentinel (65535/3584) – focus on `system-fcntl` variants and minimal scaffolding.
- Compile probes to `sb/build/*.sb.bin` with `book.api.sbpl_compile`.
- Decode with `book.api.decoder` into joinable records under `out/` (node fields, tag, u16 role, literal refs).
- Compare to existing inventories (field2-filters unknowns). Record whether any high payloads are reproduced; if negative, log explicitly in Notes and keep code.
- Iterate probes (ordering, literals, allow/deny shapes) until either a reproduction or a clear negative boundary is established for each cluster. Update Report with how negatives shape next steps.
- After exhausting SBPL reproduction for `airlock`, pivot to A-first layout checks:
  - Brute-test whether “edge” u16 fields behave like branch offsets under candidate strides (8/10/12) and whether the `sys:airlock` reachability slice expands under the offset interpretation.
  - Artifacts: `stride_offset_scan.py` → `out/stride_offset_scan.json`, `airlock_subgraph.py` → `out/airlock_subgraph.json`.
