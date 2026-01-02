# Experiment suite: graph-shape-vs-semantics

Purpose: test whether SBPL/graph encodings with the same intended allow/deny semantics but different shapes (nesting, ordering, sharing) produce equivalent runtime behavior on this world (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`), and what that reveals about PolicyGraph structure/tag interpretation.

Derived outputs are written under `out/derived/<run_id>/` and are stamped with upstream packet provenance.

## Evidence cards

### Structural variants, same intent
- Claim: pairs/families of profiles that are semantically equivalent (same allow/deny intent) but structurally different (flattened vs nested, reordered filters, duplicated vs shared subgraphs) yield indistinguishable runtime outcomes on fixed probes.
- Signals: decoded graphs showing structural differences; runtime logs showing identical allow/deny outcomes for the probe scenarios; mismatches highlight structural features that matter semantically.
- IR path: decoded graphs and runtime outcomes in `out/` feed a validation job (e.g., `graph-shape-equivalence`) that informs assumptions about tag meaning and reconstruction; results may adjust documentation around tag layouts/metafilters rather than mappings directly.

### Tag/layout sensitivity check
- Claim: altering tag assignments or node tagging patterns (while keeping SBPL intent constant) is semantically irrelevant within the modeled tag set; differences in behavior suggest gaps in tag interpretation.
- Signals: comparisons of node tags/layouts between variants; runtime outcomes on identical probes; any behavioral differences point to tag/field interpretations that need refinement.
- IR path: artifacts in `out/` compared against current tag-layout assumptions (`book/evidence/graph/mappings/tag_layouts/tag_layouts.json`) and decoder expectations; informs whether reconstruction rules capture the right semantics.

## Experimental design

- Vary: graph shape (nesting vs flattening, filter ordering, shared vs duplicated subgraphs), node tagging within the modeled tag set.
- Hold fixed: semantic intent (plain-language allow/deny description), probe scenarios (inputs/paths/syscalls), host baseline and mappings (vocab, tag-layouts, system profile context).
- Expected contrasts:
  - Changes believed semantically irrelevant should yield identical runtime outcomes; structural diffs stay in decode only.
  - If behavior diverges, it suggests the structural element (ordering, tagging, sharing) carries semantic weight not captured in current assumptions.
- Interpretation:
  - Support: “different graph, same behavior” increases confidence in current IR/tag interpretations and reconstruction heuristics.
  - Ambiguous: no signal because probes failed to hit differences; mark as inconclusive.
  - Against: behavioral differences where intent is fixed indicate gaps in tag meaning or reconstruction; feed back into tag/layout or metafilter understanding.
