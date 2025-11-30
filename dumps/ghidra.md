# Guidance for the user

# Preliminary impacts

- `node-layout`, `tag-layout-decode`, `probe-op-structure`: reverse PolicyGraph node structs and per-tag layouts directly from `Sandbox.kext` evaluation code to replace stride heuristics and expose literal/regex operands; settle tag 26/27 ambiguity in system blobs.
- `field2-filters` + `anchor-filter-map`: recover filter dispatch tables and filter-ID constants used in node evaluation to prove whether `field2` is the filter key and to map high/unknown IDs (e.g., in `airlock`) without anchor heuristics.
- `op-table-operation` + `op-table-vocab-alignment`: locate operation pointer table definitions and Operation ID enum in `Sandbox.kext`/`libsandbox` to ground bucket values against real op_count/op IDs and verify bucket→operation binding rules.
- `sbpl-graph-runtime` + `runtime-checks`: follow compiled-graph interpreter paths to understand decision/logging flag encoding in decision nodes, predict runtime outcomes without probes, and reconcile bucket-4 vs bucket-5 behavior.
- `entitlement-diff`: trace SBPL template selection/parameterization in `libsandbox`/`sandboxd` (entitlements feeding `(param ...)` and profile choice) to generate per-entitlement compiled blobs for the runtime harness.

# Agent plan

- Use Ghidra to lift `Sandbox.kext` and `libsandbox.dylib` (from the host dyld cache) and identify structures for PolicyGraph nodes, operation pointer table, and literal/regex tables.
- Extract enums and dispatch tables for Operation IDs and Filter IDs (name and numeric ID), plus any argument schemas if surfaced.
- Map node tag layouts (size, edge fields, operand slots) to confirm literal/regex operand positions and decision/logging flag bits.
- Trace the loader/compiler path to confirm Binary Profile Header fields, section offsets, and format-variant switches (modern graph vs legacy decision-tree).
- Follow entitlement-driven profile selection and parameterization code paths to understand how compiled profiles are chosen and parameterized at launch.
