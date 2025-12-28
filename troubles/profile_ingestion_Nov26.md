# Profile ingestion – modern heuristic

## Context

- Host: Sonoma baseline (see `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world.json)`).
- Script: `profile_ingestion.py`.
- Goal: upgrade “unknown-modern” profile ingestion to a cautious graph-aware heuristic that can at least recover op-table and section boundaries for modern graph-based blobs.

## Summary

- Modern profile ingestion was upgraded from “unknown-modern” to a heuristic that:
  - pulls an `operation_count` from the preamble,
  - slices the op-table accordingly,
  - and splits nodes vs literal/regex pools by scanning for printable tails.
- On `sample.sb.bin` this produces plausible sections (9 ops → 18-byte op table, ~395-byte node area, ~154-byte literals) while keeping legacy decision-tree handling intact.
- We still cannot lift filter vocab or node counts for modern blobs because node encodings are not fully decoded; vocab generation will require either a richer node parser or an external name↔ID map keyed by OS/build.

## Running notes

- Observed `sample.sb.bin` (583 bytes) shows a 16-byte preamble of small u16s, followed by 9 u16 values that look like op-pointer entries; literals live near the tail (`usr`, `dev`, `system`, `/tmp/sb-demo`).
- Updated `profile_ingestion.py`:
  - Added `modern-heuristic` header path: uses u16 word[1] as `operation_count` when it’s small and sane.
  - Slices op-table at offset 0x10 for `op_count * 2` bytes; nodes run until a printable tail is detected; remainder is literals/regex.
  - Legacy decision-tree path unchanged.
- Result on `sample.sb.bin`: Header(format_variant='modern-heuristic', operation_count=9, raw_length=583); sections → op_table=18 bytes, nodes=395 bytes, regex_literals=154 bytes.
- System profiles (`airlock.sb.bin`, `bsd.sb.bin`) now classify as modern-heuristic but still lack node/filter decoding.
 
## What’s still needed for vocab tables

- Modern blobs do not embed operation/filter names; only IDs and indices. To emit vocab tables we need:
  - A decoder for modern node records (node tag, filter key codes, literal/regex indices) to at least extract filter key IDs.
  - An external name↔ID map per OS/build to label operation and filter codes (the blob alone is not self-describing).
- Next steps:
  1) Reverse-engineer modern node encoding to recover node counts and filter key codes.
  2) Seed vocab with substrate’s operation/filter maps and align with decoded IDs/op-table entries per OS/build/format.
  3) If decoding stalls, emit counts/offsets only and document the gap in `graph/mappings/vocab/`.
