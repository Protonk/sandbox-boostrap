# Node Layout Experiment – Running Notes

## 2025-11-27 1

- Baseline blob: `book/examples/sb/build/sample.sb.bin` (583 bytes). Heuristic slices:
  - op_count=9 → op-table length 18 bytes (offset 0x10..0x21).
  - nodes: ~395 bytes.
  - literals/regex: starts at offset ~0x1ad (429), length ~154 bytes. Literal tail shows strings: `/etc/hosts`, `usr`, `dev`, `system`, `/tmp/sb-demo`.
- Quick stride scan on node region:
  - stride 8: tags {0,1,2,3,5,7,8}, all edges in-bounds (interpreting two u16 edges), distinct edges ~6.
  - stride 12: tags {0,3,5,7,8}, edges in bounds 63/64, distinct edges ~8.
  - stride 16: tags {1,3,7,8}, edges in bounds 48/48, distinct edges ~3.
  - 12-byte stride looks promising: more tags than 16, fewer junk tags than 8; edge fields mostly small/bounded.
- Sample record dump @stride=12 (fields: tag, edge1, edge2, literal_idx?, extra):
  - (0, 8, 8, 7, 8, extra=08000700)
  - (1, 7, 7, 8, 8, 08000500)
  - (2, 5, 5, 5, 8, 08000700)
  - (3, 8, 3, 3, 3, 03000300)
  - … many records with tags 7/8 and edges 7/8; occasional literals 1/2 near later records.
  - Offsets suggest: byte0=tag, bytes2-3=edgeA, bytes4-5=edgeB, bytes6-7=literal/regex index candidate.
- Literal region starts at offset 429; many node records show lit index 8 or 3. Need a variant profile to see lit index changes.
- Next steps (not yet done):
  - Compile minimal SBPL variants (single operation; add one `subpath` literal, then change literal) to diff node bytes and confirm which field is the literal index.
  - Automate scoring over strides/fields; check that literal field points into literal pool (index×? lands near `/tmp/...` offsets).
  - Apply candidate layout to `airlock.sb.bin`/`bsd.sb.bin` to see if stride/tag pattern holds and if edges stay in bounds.

## 2025-11-27 2

- Created minimal SBPL variants under `book/experiments/node-layout/sb/`:
  - `v0_baseline`: allow `file-read*` only.
  - `v1_subpath_foo`: allow `file-read*` with `(subpath "/tmp/foo")`.
  - `v2_subpath_bar`: same with `/tmp/bar`.
  - `v3_two_filters`: `(require-all (subpath "/tmp/foo") (subpath "/dev"))` on `file-read*`.
- Compiled with `sandbox_compile_string`:
  - v0 len=440, ops=5, nodes=387, literals=27.
  - v1/v2 len=467, ops=6, nodes=365, literals=74.
  - v3 len=440, ops=5, nodes=387, literals=27.
- Stride=12 node slices:
  - v1 vs v2: node regions are identical (no differing records), so changing literal from `/tmp/foo` to `/tmp/bar` did not change node bytes (literal table differs; literal pool contains `/tmp/foo` in v1). Suggests literal indices may be encoded elsewhere or nodes reference a shared literal index that didn’t change across these two strings.
  - v0 vs v1: 31 records differ; op_count increases (5→6) and literals grow. Indicates adding a `subpath` filter changes node region but not in a way that distinguishes foo vs bar.
  - v0 vs v3: 2 differing records; both have same op_count (5). Diffs show only literal index changes (e.g., record 2 lit 3→4) and tag change in record 3 (3→4). Hypothesis: adding a second filter tweaks literal indices but keeps node count constant when op_count unchanged.
- Literal pools:
  - v0/v3 literals are short, no path strings visible (pure metadata?).
  - v1 literals contain `/tmp/foo`; v2 literals contain `/tmp/bar`. Node bytes unchanged between v1 and v2, so literal index field at bytes6-7 may be a small ID independent of the literal table position, or the literal pool order is fixed and both literals share the same index bucket.
- Open questions:
  - How to map literal indices to actual offsets; current heuristic doesn’t link node field to literal pool address.
  - Whether a different filter type or additional literal would change the node bytes enough to isolate the literal index field.
- Next steps:
  - Add a profile with two distinct literals for the same filter type (e.g., two subpaths) to see if node records diverge.
  - Try stride 8/16 again on v1/v2 to see if any field changes with foo→bar.
  - Consider parsing the op-table entrypoints to anchor which records belong to which operation.

## 2025-11-27 3

- Added open questions to Plan.md (literal index mapping, multiple literals, filter key location, op-table anchoring).
- Still need a variant with two distinct literals in the same profile to force literal index differences; current v1 vs v2 suggests literal field isn’t simply “literal pool offset.”
- Possible next probes:
  - Profile with `(allow file-read* (require-any (subpath "/tmp/foo") (subpath "/tmp/bar")))`.
  - Profile with different filter types (e.g., `literal` vs `subpath`) to see if tag or field changes more clearly.
  - Use op-table entrypoints to segment node array per operation and see if edge fields line up with op_count changes (5→6).

