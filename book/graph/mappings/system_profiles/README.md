# System profiles

Canonical system-profile digests live here.

Current artifacts:
- `digests.json` – Per-profile digest (op-table buckets, tag counts, literal sample, sections, validation) for curated system blobs (`airlock`, `bsd`, `sample`) on this host/build.
- `attestations.json` + `attestations/*.jsonl` – Cross-linked attestations for system and golden profiles (blob sha256, op-table entries, tag counts, literal/anchor hits, tag-layout hash, vocab versions, runtime links when available).

Role in the substrate and CARTON:
- These digests are compact, decoder-backed views of real platform **Profile layers** and their compiled **PolicyGraphs**. They provide stable examples of op-table shapes, tag distributions, and literal content for system Seatbelt profiles.
- Other experiments (op-table, tag-layouts, anchors, field2) treat these as ground-truth reference profiles when checking structural hypotheses, and the textbook uses them as worked examples of how SBPL templates, entitlements, and containers manifest in compiled policy.
- Attestations connect these static snapshots to vocab/tag-layout versions, anchor coverage, and runtime traces so downstream tools can mechanically join structure ↔ literals ↔ runtime outcomes.
- CARTON manifest: `book/graph/carton/CARTON.json` freezes the hashes/paths for Sonoma 14.4.1 system profile digests and their validation IR as part of the CARTON set the textbook and API read.
