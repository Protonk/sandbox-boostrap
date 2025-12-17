- Initialized experiment scaffold. Report links to upstream inventories (`field2-filters`, `probe-op-structure`, `tag-layout-decode`, `system-profile-digest`, `golden-corpus`) and records prior failed probes (e.g., `bsd_tail_context.sb`, `dtracehelper_posixspawn.sb`, kernel immediate searches).
- No local probes run yet; `out/` is empty pending new SBPL variants for `bsd` tag-26/tail and `airlock` high tags.
- Expect to author SBPL under `sb/` and keep decoded node inventories under `out/` for cross-comparison with existing field2 census.
- Added initial probes and harness:
  - `sb/bsd_tag26_matrix.sb` (right-name/preference-domain/literal mix + basic file/process ops).
  - `sb/airlock_system_fcntl_variants.sb` (system-fcntl allow/deny matrix plus minimal scaffolding).
  - `run_probes.py` compiles all `sb/*.sb` via `book.api.sbpl_compile` and decodes to `out/decode_records.jsonl` and `out/field2_summary.json`.
- Run result (negative for target highs): `out/field2_summary.json` shows only low/vocab values in the bsd probe ({6,5,0}) and no appearance of the bsd highs (170/174/115/109/16660). Airlock probe did not surface 165/166/10752; instead it shows low IDs {8,7,3,2,0} plus a single hi-bit payload `0xce00` (hi=0xc000, lo=3584) on tag 0. Pending follow-up to see if 0xce00 is reproducible or incidental; main targets remain unreproduced.
- Added two richer probes:
  - `sb/bsd_tag26_richer.sb` (more right/preference variants, bsd literals, broader ops including sysctl and mach-lookup).
  - `sb/airlock_system_fcntl_wide.sb` (wider fcntl-command sweep including larger values, alternate allow/deny shapes, light scaffolding).
  - Re-ran `run_probes.py`; both new profiles compiled but decode to zero nodes (node_count=0), leaving no records in `decode_records.jsonl`. Negative/empty result; suggests this SBPL shape collapses under the compiler or is being optimized away. No new sightings of target highs; earlier `0xce00` sentinel from `airlock_system_fcntl_variants` remains the only hi-bit payload observed locally.
- Varying system-fcntl context before touching decode/stride:
  - Added `sb/airlock_system_fcntl_minimal.sb` (only system-fcntl allow statements) and `sb/airlock_system_fcntl_context.sb` (mix of allow/deny with fcntl-command 0/1/1024 plus file-read/write literals, mach-lookup, process-info*, sysctl-read).
  - Re-ran `run_probes.py` (now compiles 6 probes). Results:
    - `airlock_system_fcntl_minimal` decodes with nodes and only low IDs {4,3}; no highs.
    - `airlock_system_fcntl_variants` unchanged: low IDs {8,7,3,2,0} plus a single `0xce00` hi-bit payload on tag 0.
    - `airlock_system_fcntl_context` decodes to node_count=0 (empty profile).
    - `airlock_system_fcntl_wide` and `bsd_tag26_richer` remain node_count=0; `bsd_tag26_matrix` still only low IDs {6,5,0}. Target highs remain unreproduced.
  - Open question: why some multi-statement fcntl probes collapse to zero nodes—compiler normalization vs SBPL shape? No decode/stride tweaks yet per instruction.
- Further fcntl shape sweeps:
  - Added `sb/airlock_system_fcntl_split.sb` (small allow/deny set with a larger command) and `sb/airlock_system_fcntl_gate.sb` (mach-lookup gate + fcntl allow/deny). Also set the harness to skip `.gitkeep`.
  - Re-ran `run_probes.py` (8 probes). Results (`out/field2_summary.json`):
    - `airlock_system_fcntl_gate`: only low IDs {7,6,5,4,0}; no highs.
    - `airlock_system_fcntl_split`: low IDs {7,6,0,5,1} plus a single low payload 1024 (`0x400`); no highs.
    - `airlock_system_fcntl_minimal`: unchanged low IDs {4,3}; `airlock_system_fcntl_variants` still the only case with `0xce00` hi-bit payload on tag 0.
    - `airlock_system_fcntl_context`, `airlock_system_fcntl_wide`, `bsd_tag26_richer` remain node_count=0; `bsd_tag26_matrix` still only low IDs {6,5,0}. Airlock highs 165/166/10752/0xffff and bsd highs remain unreproduced.
- Additional minimal shapes:
  - Added `sb/airlock_system_fcntl_single0.sb` (single allow) and `sb/airlock_system_fcntl_literal_guard.sb` (file literal + single allow). Harness now compiles 10 probes.
  - Results (`out/field2_summary.json`):
    - `airlock_system_fcntl_single0`: only low IDs {4,3}; same as minimal.
    - `airlock_system_fcntl_literal_guard`: only low IDs {5,4,3}; no highs.
    - `airlock_system_fcntl_gate`, `split`, `minimal`, `variants` unchanged (variants still the only source of `0xce00`); `context`, `wide`, `bsd_tag26_richer` still empty; `bsd_tag26_matrix` unchanged with low IDs. No appearance of target airlock highs or bsd highs; `0xce00` remains an isolated anomaly in the variants profile.
- Treat the system-fcntl SBPL shape/context sweep as exhausted for this host baseline; further progress likely requires layout-focused analysis on the canonical blobs and/or non-SBPL evidence (encoder/evaluator).

- Began A-first layout checks (edge-as-offset vs edge-as-index):
  - Added `stride_offset_scan.py` and ran it to produce `out/stride_offset_scan.json` (brute parses with strides {8,10,12} from `nodes_base=16+(op_count*2)` and treats the first two u16 fields as branch targets for tags {0,1,26,27,166}).
  - Airlock signal: under stride=12, tag-166 branch targets frequently land on ASCII-looking starts (e.g., `(tag,b1)=(108,116)`), while under stride=8 the same tag-166 branches mostly land on `(tag,b1)=(166,0)` and `(159,0)` with `b1==0` (more “node-like”). This supports the hypothesis that the airlock “7-node graph” view is a stride/offset misinterpretation artifact.
  - Airlock payload note: scanning under stride=8 finds many tag-166 records whose third u16 field takes values 165 and 166; the previously-seen 10752 (`0x2a00`) does not show up in that slot under stride=8, suggesting the 12-byte decode’s 10752 may be misgrouping-dependent.
  - bsd signal: tag-26 records in the canonical bsd blob show field0 always in-range (targets mostly tags 27/0/26), while the unknown-high tag-26 cases have field1 values like 2560/1536/1792/12800 that are far out-of-range for node-index semantics (and do not fit as simple literal offsets either). This points to tag-26 field1 likely not being a branch target in those cases.

- Airlock graph expansion witness:
  - Added `airlock_subgraph.py` and ran it to produce `out/airlock_subgraph.json`.
  - Treating the op-table entry at index 162 as `system-fcntl` (op-table value 5 in the canonical airlock blob), the reachable set from that root differs materially by stride:
    - stride=8: reachable_count=10 (focus tags 6; plausible non-ASCII/b1==0 nodes 8).
    - stride=12: reachable_count=4 (focus tags 3; plausible non-ASCII/b1==0 nodes 3).
  - Under stride=8, the `system-fcntl`-root reachable slice includes additional non-focus tags (e.g., 157/159) and a tag-166 node carrying a 3584 value in-field; the corresponding stride=12 slice stays near the tiny, self-referential structure.
- Refined `stride_offset_scan.py` to include per-source-tag target histograms (e.g., tag-166 target `(tag,b1)` distributions) and regenerated `out/stride_offset_scan.json`.

- Slot 3/4 histogram (12-byte decode view):
  - Added `canonical_slot_hist.py` and ran it to produce `out/canonical_slots34_hist.json` (per-tag histograms for fields[3]/fields[4] under the current 12-byte record decode).
  - bsd: tag-26 nodes show low-entropy slot patterns: field3 is mostly {26,27} and field4 mostly {27,26} (with a small number of outliers); tag-27 similarly concentrates on {26,27}.
  - airlock (as currently decoded under 12-byte records): tag-0 has field3=1002 and field4=39 (single instance); tag-166 field3 is mostly 166 with one 2; field4 is mostly 166 (plus a 165 and 32769).

- Stride=8 framing cross-check (byte-level witness + scale=8 vs scale=12 comparisons):
  - Added `stride8_decoder_crosscheck.py` and ran it to produce `out/stride8_decoder_crosscheck.json`.
  - bsd spillover witness (aligned under both 8- and 12-byte framings) at `abs_off=360` (`rel_off=288` from `nodes_base=72`): under an 8-byte record view the current record is `tag=26 kind=0 fields=[26,27,27]`, the next record begins at `abs_off+8` with `tag=26 kind=0 fields=[27,27,27]`, and the 12-byte view at `abs_off` necessarily consumes 4 bytes from that next record (`fields[3]=26` == next record (tag,kind) as u16; `fields[4]=27` == next record’s first u16).
  - airlock op_table scaling witness: scoring `op_table[i]` as offsets under scale=8 vs scale=12 shows scale=12 dominated by ASCII tag/kind pairs (top `(108,116)` = “lt”), while scale=8 lands on mostly non-ASCII `kind=0` headers (top `(159,0)`, `(157,0)`, …). This is a strong witness that op_table entries are offsets in 8-byte words (and the 12-byte node framing produces false “literal start” / truncation artifacts).

## Updated

- Updated: reran the stride/scale cross-check scripts (`stride8_decoder_crosscheck.py`, `airlock_subgraph.py`, `stride_offset_scan.py`, `canonical_slot_hist.py`) to refresh `out/*` under the current decoder framing. The core witnesses still hold.
- Updated: with the stride=8 framing promoted into shared tooling, the `sys:bsd` “high field2” cluster is treated as resolved-by-framing (those values were decode artifacts under the old 12-byte approximation). Remaining work here is now strictly about the `sys:airlock` survivors from `field2-filters`’ unknown census (currently `165` and `49171`) and any probe-only sentinels.
