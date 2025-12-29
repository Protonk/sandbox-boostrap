# Golden Corpus – Plan

> Archived experiment scaffold. Canonical corpus lives under `book/graph/concepts/validation/golden_corpus/`.

## Purpose
Stand up a small, host-bound regression corpus for compiled sandbox blobs so decoder/op-table/inspection surfaces have a stable reference set. The corpus should capture header/section layout, tag histograms, literal offsets, and hashes to detect drift when tag layouts or decoder heuristics change.

## Questions
- Which compiled blobs give good coverage of common shapes (allow-all, deny-all, bucketed file-read, literal-heavy probes)?
- How do decoder outputs align with the profile_tools inspector and op-table summaries on those blobs?
- What minimal signals should be guarded (op_count, nodes length, literal start, tag histogram, layout digest)?

## Plan
1. Select 4–6 existing blobs (golden-triple + representative probes) and record their hashes plus provenance in a manifest; include static-only platform/system profiles via the fixture blob set (no runtime apply).
2. Run decoder and profile_tools inspectors on each blob; store raw header/section slices and decoded JSON in `book/graph/concepts/validation/golden_corpus/`.
3. Build a consolidated `corpus_summary.json` with key signals and the tag-layout digest used.
4. Keep the validation job `experiment:golden-corpus` aligned with the manifest/summary under `book/graph/concepts/validation/golden_corpus/`.

## Out of scope
- Regenerating system profile blobs (apply-gated here); note the gap as a future addition.
- Changing decoder heuristics or tag layouts.
