# Post-remediation promotion proposal

> world_id: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`

This document makes a scoped, post-remediation argument that three specific structures in the SANDBOX_LORE world can now be treated as “bedrock” for this host. For the initial framing and earlier state, see the original proposal in [`promotion-proposal.md`](promotion-proposal.md):

1. The Operation and Filter vocabularies (196 Operations, 93 Filters) harvested from this host’s `libsandbox`.
2. The “modern-heuristic” compiled profile format, together with per-tag layouts for the literal/regex-bearing tags we currently cover.
3. The decoded structure of three curated system profiles: `sys:airlock`, `sys:bsd`, and `sys:sample`.

This note is a snapshot and justification for the first promotion decision. The live registry of which surfaces are currently bedrock lives in [`book/graph/concepts/BEDROCK_SURFACES.json`](../book/graph/concepts/BEDROCK_SURFACES.json); check that file (and its mirrors) for the authoritative set as the world evolves.

Earlier, these were already important ingredients in the project’s story, but the supporting machinery around them was thinner and more informal. Since then, the repo has gained dyld slice manifests, adversarial runtime experiments, per-op coverage tracking, canonical contract generation with tested demotion, and explicit “Claims and limits” texts tying all of this together. The question here is not whether these concepts are “true for all time,” but whether, for this specific world, they can safely be treated as fixed inputs to downstream tools and explanations, with clear evidence and a path for demotion if the world shifts.

The sections that follow describe, for each concept, what the claim actually is, how it is represented and used, what now backs it, and where its boundaries lie. The aim is to surface the reasoning and the operational story, not only the file paths.

---

## What “bedrock” means in this world

Within this project, declaring something “bedrock” is a decision about how much you are willing to lean on it, not a metaphysical guarantee about the macOS sandbox forever.

For this world, “bedrock” now means:

* You are willing to treat a mapping as a fixed input when building other tools, CARTON queries, and chapter-level explanations. That is, you will not second-guess it in every downstream use.
* That willingness is backed by multiple kinds of evidence: static analysis, decoding, adversarial runtime checks where possible, and consistency across different mapping layers, not just a single experiment that once passed.
* There are explicit guardrails and contracts. If the upstream binaries, profiles, or decoder behavior drift, status flips away from `ok`, guardrail tests go red, and downstream mappings inherit the degraded status rather than silently continuing to treat old assumptions as true.

The rest of this proposal should be read with that meaning in mind. “Bedrock” here is scoped to one named baseline (`sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`), and it comes with a falsification story: manifests, contracts, status flags, and demotion tests are the mechanisms by which it can be revoked.

## Audit context and remediation arc

The earlier promotion note in [`promotion-proposal.md`](promotion-proposal.md) was already careful by ordinary standards, but a dedicated audit—summarized in [`web-agent-audit.md`](web-agent-audit.md)—showed that it leaned too heavily on narrative phrases like “multiple converging routes” and “status: ok” without enough machinery to make those claims stick, or to sharply delimit what they did and did not cover. The remediation work documented in this repo is largely a response to that audit: it makes common‑mode risks explicit, adds stress tests where the static model could be wrong, and encodes boundaries and demotion paths so that “bedrock” is backed by concrete contracts rather than just prose.

For the Operation and Filter vocabularies, the audit noted that the original story—“196 Operations harvested from dyld, stable across op‑table experiments and system profiles”—was roughly right but incomplete. It highlighted: (1) a shared dependency on a single libsandbox slice and `_operation_names` table, so a bad slice could quietly poison `ops.json`, alignment, and digests together; (2) no way to distinguish operations with runtime evidence from those that were only “name + ID”; and (3) an overuse of “independent routes” language while everything still flowed through one decoder and one set of binaries. The remediation tightened the epistemic story: a manifest plus guardrail for trimmed dyld slices pins the source vocab table; an adversarial runtime suite exercises key ops (file‑read*, file‑write*, mach‑lookup) under deliberately tricky profiles; and `ops_coverage.json` marks, per op, which have structural and runtime backing. The underlying claim—“for this world, these 196 names and IDs describe the libsandbox operation table the kernel actually sees”—is now tied to explicit provenance, coverage, and failure modes.

For the modern format and tag layouts, the audit found that the original “modern‑heuristic” label compressed too much: it treated a small set of literal/regex tags as structural fact without making the scope and limits explicit. In particular, it blurred the line between “layout is bedrock” and “semantics are still partly heuristic,” and it was easy to misread as claiming “tag layouts” in general rather than a carefully evidenced subset. There was also no mechanical link between canonical profile health and tag‑layout demotion. Remediation responded by narrowing and hardening the claim: `tag_layouts.json` now explicitly lists the covered tags; hash‑based tests enforce that only metadata changes can leave the contract hash untouched; tag‑layout metadata imports canonical profile status so drift demotes layouts automatically; and both docs and code now say, in effect, “for these tags, the 12‑byte layout (sizes and offsets) is treated as fixed because decoder‑side inference and compiler‑side emission agree; unknown tags remain stride‑12 heuristics with semantic caveats.”

For the canonical system profiles, the audit flagged that the first report used `sys:airlock`, `sys:bsd`, and `sys:sample` as heavy anchors for tag layouts, coverage, and CARTON, while relying on digests and static checks built on the same decoder stack and offering no mechanical demotion path. Apply‑gated profiles could not be validated end‑to‑end at runtime, yet were still treated as bedrock about kernel behavior. The remediation introduced explicit contracts bundling blob SHA/size, op‑table hash/len, tag counts, tag‑layout hash, and world pointer; tests that enforce those contracts and flip status to `brittle` on drift; propagation of degraded status into tag layouts and coverage; attestations that walk literals and anchors independently; and CARTON manifest coverage so clients cannot silently pick up inconsistent digests. The scope of the claim is now narrower but clearer: bedrock here is “which blobs the kernel consumes for these profiles and what their decoded structure looks like on this host,” not “their behavior has been exhaustively tested at runtime.”

More broadly, the audit pushed the project to be explicit about static IR vs runtime behavior, and about its own standards. The first proposal’s cross‑check story (“Apple artifacts + decoder + some runtime checks agree, so static IR is a good proxy”) had no adversarial profiles and treated the kernel as a black box. The remediation added a runtime‑adversarial suite with a clear “Claims and limits” section and promoted tests that confirm only a bounded set of operations and shapes have been stress‑tested, with known discrepancies (like `/tmp`→`/private/tmp` VFS effects) documented as out‑of‑model phenomena. At the same time, “bedrock” itself was re‑defined more tightly: scoped to this world, explicitly limited to particular ops/tags/profiles, and always accompanied by a demotion story and coverage indicators. The rest of this proposal is written against that post‑audit standard.

---

## 1. Operation vocabulary (196 ops / 93 filters)

### What is being claimed

For this Sonoma world, the Operation and Filter vocabularies are defined by two JSON tables (summarized in [`book/graph/mappings/vocab/README.md`](book/graph/mappings/vocab/README.md)):

* [`book/graph/mappings/vocab/ops.json`](book/graph/mappings/vocab/ops.json)
* [`book/graph/mappings/vocab/filters.json`](book/graph/mappings/vocab/filters.json)

These tables are pinned to this world via metadata (explicit `world_id` and `status: ok`) and are ordered exactly as harvested from this host’s `libsandbox` within the dyld shared cache. When you say “operation 96 is `mach-lookup`” or “these are the operations this host knows about,” you are referring to entries in these two files.

The crucial point is that these vocabularies are frozen to the host’s own published tables, not to the subset of operations you have happened to exercise in SBPL or runtime probes. In practice, “only allowed op/filter names” for this world means “the only names we recognize are those exported by this host’s libsandbox; if Apple adds names to that table, they will appear in a fresh harvest and force a change in status.”

### How the vocabularies are used downstream

These vocab files sit at the base of much of the graph:

* Op-table alignment work (see [`book/graph/mappings/op_table/README.md`](book/graph/mappings/op_table/README.md)) uses them to attach human-readable operation and filter names to op-table slots. When a synthetic profile is compiled and its op-table decoded, alignment data structures assume that the mapping from slot index to operation ID, and from operation ID to name, is given by `ops.json`.
* System-profile digests (described in [`book/graph/mappings/system_profiles/README.md`](book/graph/mappings/system_profiles/README.md)) use them whenever they talk about the number of operations a canonical profile exposes, or when they validate that op-table lengths and hashes make sense for this world’s vocabulary.
* Per-operation coverage ([`book/graph/mappings/vocab/ops_coverage.json`](book/graph/mappings/vocab/ops_coverage.json)) is built on top of `ops.json`: each operation gets a record stating whether it has structural evidence (it appears in decoded profiles or alignment experiments), runtime evidence (it is exercised in runtime-checks and runtime-adversarial), or both.
* CARTON’s operation coverage and index mappings downstream of these vocab files (see [`book/api/carton/README.md`](book/api/carton/README.md)) expose the same information to clients. When a CARTON query asks for “everything known about `mach-lookup` on this host,” it is the chain `ops.json` → coverage mappings → CARTON indices that ultimately answers.
* API helpers in `book/api/carton/carton_query.py` all assume that these vocab tables are definitive. They do not attempt to infer names or IDs from profiles; they read them from these mappings.

In other words, the vocab tables are not just one artifact among many; they are the canonical dictionary that every other layer consults when it wants to talk about operations and filters in this world.

### How the claim is supported

On the validation side, the pipeline is now quite strict:

* A dedicated validation job (`vocab:sonoma-14.4.1`) is recorded in `validation_status.json` as `ok`, pointing to the trimmed `libsandbox.1.dylib` slice as input and to the vocab mappings as outputs. The job’s metrics explicitly record “196 Operations, 93 Filters,” so a change there is visible at the validation layer.
* A test ([`book/tests/planes/graph/test_vocab_harvest.py`](book/tests/planes/graph/test_vocab_harvest.py)) compares the raw harvested name lists from the dyld-driven `vocab-from-cache` experiment to the contents of `ops.json` and `filters.json`. It asserts that the names match, the counts match, the order matches, and that IDs are exactly `0..N-1` for the recovered lists. This guards against both accidental hand edits and subtle off-by-one errors in harvest.
* Another test ([`book/tests/planes/graph/test_dyld_libs_manifest.py`](book/tests/planes/graph/test_dyld_libs_manifest.py)) checks that the trimmed dyld slices under `book/graph/mappings/dyld-libs/` still have the expected path, size, and SHA-256. This pins the binary source of the vocab tables themselves; if you silently swap in a different libsandbox slice, the manifest check will fail.

Cross-checks then make sure that this vocabulary is actually coherent with the rest of the world:

* Op-table alignment mappings re-use the same IDs and record which slots in the op-table “light up” when you compile profiles that exercise individual operations. These mappings carry their own metadata and status, and tests check that the vocab IDs they reference are consistent.
* System-profile digests record op-table lengths and hashes for canonical profiles, and those values are expected to be consistent with a 196-entry vocabulary. If a canonical profile suddenly had an op_table_len that did not match the vocab size, static checks would catch it.
* The per-operation coverage mapping (`ops_coverage.json`) and the CARTON coverage derived from it act as a reality check for the subset of operations you have actually run through the kernel. For operations like file-read*, file-write*, and mach-lookup, these artifacts assert that both structural and runtime evidence exist; for the rest, they mark the lack of runtime data explicitly.

There is also a genuine independence story. The vocab harvest route reads from the dyld cache using only symbols and raw string tables, with no reference to profile decoding or runtime behavior. The profile/decoder route goes through SBPL, libsandbox compilation, and the shared decoder, and then interprets op-tables using the vocab. A serious error in the vocab would require both the harvest and the decoding direction to be wrong in a perfectly compatible way. The manifest and harvest tests are there to make that kind of common-mode error less plausible.

### Where the claim stops

This vocabulary is explicitly bound to a single host and world. It does not say “there are exactly 196 operations in some abstract macOS sense”; it says “this host’s libsandbox exposes a 196-entry operation table, and that is the table we will use as the universe of Operations here.”

The claim also does not assert that every operation is well understood in terms of semantics. Many entries are still “name + ID only” with little or no runtime exploration behind them. That is why `ops_coverage.json` exists: it distinguishes the few operations for which you have both static and adversarial runtime evidence from the long tail that is only structurally present. Bedrock, in this section, is about the vocabulary itself—names, IDs, ordering, and completeness for this world—not about the semantic behavior of each entry.

If libsandbox on this host ever changes—new strings, reordering, or a different binary slice—the manifest and vocab tests will fail. Regenerating vocab will either produce changed tables (forcing you to confront the difference) or make it obvious that you are no longer talking about the same world. That is the demotion path: the system is not designed to “auto-heal” such a change in the background.

---

## 2. Modern compiled profile format and tag layouts

### What is being claimed

SANDBOX_LORE’s world model assumes that, on this host, the system and synthetic profiles it cares about are all instances of a single “modern-heuristic” profile format. This format consists of a small header, an op-table, a node region, and a literal/regex pool. The bedrock claim is not that every last byte of that format is exhaustively understood; it is that for a carefully chosen subset of tags—the literal/regex-bearing tags that carry most of the interesting structural information—you now know exactly how their 12-byte node records are laid out and can treat that layout as fixed.

That layout information lives in [`book/graph/mappings/tag_layouts/tag_layouts.json`](book/graph/mappings/tag_layouts/tag_layouts.json). For each of the covered tags (currently 0, 1, 3, 5, 7, 8, 17, 26, 27, 166), this mapping records the record size and which halfwords are edges versus payload. The decoder for this world uses these layouts directly when it turns raw node bytes into structured PolicyGraph information.

The important shift after remediation is that “heuristic” is now confined to the parts of the format you have not yet nailed down, rather than being a blanket disclaimer. For the tags in `tag_layouts.json`, you no longer think of the layouts as a clever guess; you treat them as a contract, with supporting evidence.

### How these layouts are used

These tag layouts are threaded through several layers of the project:

* The decoder consults `tag_layouts.json` whenever it encounters one of the covered tags. Instead of assuming that node records are uniform and hoping the fields line up, it dereferences the mapping and interprets each halfword appropriately. This is what allows it to reconstruct which literal pool entries a node references, or how filter IDs and field2 values are encoded for those tags.
* Static checks for canonical system profiles compute a `tag_layout_hash` that depends on the set of tags and their layout structure as understood by the decoder. That hash is stored alongside other structural metadata (tag counts, section sizes) and acts as a fingerprint of “the tag-layout story” for a given blob.
* The digests for canonical system profiles import this `tag_layout_hash` and treat it as part of each profile’s contract. In effect, the canonical profile contracts assert: “these blobs are not only this large and have this op-table hash; they also agree on the tag layouts being used to interpret them.”
* A small annotator script reads canonical profile status and world pointers and writes that information into `tag_layouts.json` as metadata. This ensures that when canonical profiles are demoted, the tag layouts inferred from them are demoted as well. Tag layouts do not “float free” of their evidence.
* Later mapping and runtime work—such as relating anchors to filters, or decoding runtime signatures—leans on these layouts whenever it needs to talk about “the node that carries this literal” or “the tag that encodes this set of filters.”

In short, these layouts are how PolicyGraphs get their semantic teeth. Without them, the node region is just a stream of 12-byte records with opaque integers.

### How the claim is supported

The evidence for treating these layouts as bedrock rather than mere heuristics comes from two complementary directions.

From the decoder side, you have an experiment that starts with compiled blobs—canonical profiles and synthetic probes—and works its way up (see `book/experiments/tag-layout-decode/Report.md`). It groups nodes by tag, looks at their observed patterns, and infers which fields are edges, which are payloads, what the record sizes are, and how literal pool indices are distributed. It then promotes this inferred structure into `tag_layouts.json`. Validation tests make sure that this file exists, that the tags it claims to cover are present, and that any structural change to the layouts will flip the computed hash. This route treats the compiled blob as ground truth and asks, “What layout would explain the bytes we see?”

From the compiler side, you have a different experiment that starts with `libsandbox`’s emit paths. It uses SBPL matrices and low-level node dumps to see exactly which halfwords the encoder writes when constructing nodes for particular tags. For example, it can observe that for a certain tag, one halfword is always the tag number, another is consistently a filter ID, and the third varies in ways that correspond to field2 or literal indices. It records those observations in its own outputs. This route treats the encoder’s logic as ground truth and asks, “What layout must these nodes have, given how `libsandbox` writes them?”

After remediation, these two views have been made to meet: for the tags in the covered subset, the inferred layouts from blob decoding match the layouts reconstructed from the encoder’s behavior. Static checks tie both right back to the canonical blobs by recording a single `tag_layout_hash`. Tests ensure that this hash only changes when the tag set or their layouts change, not when you merely adjust comments or metadata.

This is what lifts the covered tag layouts from “strong but fragile educated guess” to “contracted structure.” Both the compiled output and the emitting code agree on the layout, and the mapping is wired into canonical profiles and tests.

### Where the claim stops

The project is deliberately honest about the limits here:

* Only the listed tags are treated as bedrock. Unknown tags still go through a generic 12-byte interpretation that might be good enough for some analyses but is not claimed as a fixed contract.
* The format is still labeled `modern-heuristic` in validation metadata. This acknowledges that there may be other profile formats on the system that you are not modeling, and that even within this format you have not validated every corner of the node region (for example, exotic tags or mixed-stride structures).
* The layouts are tied to canonical profiles. If those profiles change—because Apple updates a shipped profile or you discover you were decoding the wrong blob—the canonical profile contracts will detect drift, change status, and cause the tag-layout metadata to be updated accordingly. In that situation, the correct response is to re-infer or re-confirm the layouts, not to keep treating old assumptions as bedrock.

The “bedrock” stance here is therefore precise: for this world, as long as the canonical profile contracts remain undrifted and the decoder/encoder cross-checks continue to agree, the layouts recorded in `tag_layouts.json` for the covered tags can be treated as fixed structure. Beyond that, the model remains openly heuristic.

---

## 3. Canonical system profiles (`sys:airlock`, `sys:bsd`, `sys:sample`)

### What is being claimed

For this baseline, there are three system profiles that the project elevates to a special role:

* `sys:airlock`
* `sys:bsd`
* `sys:sample`

They are treated as the canonical examples of platform policy for this host. The claim is not just that they exist or that they are important, but that their compiled blobs, as seen by the kernel, are described accurately and stably by the IR captured in [`book/graph/mappings/system_profiles/digests.json`](book/graph/mappings/system_profiles/digests.json). When you say “this is what `sys:bsd` looks like on this world,” you are really pointing to the digest and contract for that profile.

Those digests serve as both a structural summary and a binding contract. For each canonical profile, they record the path to the compiled blob, the blob’s hash and size, high-level structural properties (op_count, op_table hash, tag counts, tag_layout_hash, section sizes), and a `world_id` that ties the profile back to this baseline. They also record a `status`, which is currently `ok` for all three, and a list of `drift_fields` that will be populated if any of the contract fields change.

### How these profiles are used downstream

These canonical profiles are threaded into many parts of the repo:

* Tag-layout work uses them as the source corpus from which to infer layouts. The tag layouts discussed above are ultimately grounded in the structure observed in these canonical blobs, and their metadata explicitly acknowledges this dependency.
* CARTON’s coverage and index mappings treat these profiles as the backbone of their view of the world. When CARTON answers questions like “which operations are used in real system policy?” or “which profiles cover which parts of the operation vocabulary?”, it reads from coverage and index mappings that are in turn built on these digests.
* Runtime expectations and attestations tie the canonical profiles to runtime experiments where possible. Although apply gates mean you cannot always run `sys:airlock` directly through `sandbox_apply` on this host, golden expectations and runtime manifests link SHAs and IDs so that you can see, in a unified way, how canonical profiles and runtime probes relate.
* The human-facing textbook narrative also leans on these profiles. They are the concrete examples you point to when you explain, for instance, how a system profile combines a base policy with app-specific behavior.

In effect, these three profiles anchor the project’s picture of “what the OS actually ships” for this world. That is why their integrity and status matter so much.

### How the claim is supported

The process for generating and maintaining these digests is now more disciplined and more explicit than in the initial promotion draft.

On the generation side, a single script, `generate_digests_from_ir.py`, is responsible for turning decoded IR into the canonical mapping. It insists that the upstream validation job for system-profile decoding is in good standing; if the decoding experiment is not `ok`, the generator refuses to proceed. It then calls a separate static-checks generator, reads the relevant metrics from both the decoded IR and the static checks, and assembles a contract for each profile. That contract contains a fixed list of fields—blob hash and size, op_table hash and length, tag counts, tag_layout_hash, world pointer—and a version number for the contract schema itself.

On the guardrail side, several tests keep this process honest:

* One test (`book/tests/planes/graph/test_system_profiles_mapping.py`) asserts that the canonical set is exactly the three profiles listed above, that each one carries the correct world pointer, and that each one has an `ok` status with no recorded drift. This guards against both accidental addition/removal of canonical profiles and unexamined contract changes.
* Another test (`book/tests/planes/graph/test_mappings_guardrail.py`) ensures that the mapping itself is present and has the expected shape, so a missing or malformed digests file is immediately visible.
* A “drift scenario” test (`book/tests/planes/graph/test_canonical_drift_scenario.py`) deliberately simulates a change in one of the canonical blobs (for example, by altering a recorded SHA) and checks that the system behaves as intended: the affected profile is demoted to `brittle`, its drift fields record the changed contract fields, and the overall mapping status reflects that something significant has changed.

In addition, static checks and attestations provide independent views over the same blobs. Static checks (`book/graph/mappings/system_profiles/static_checks.json`) recompute section sizes, op counts, tag counts, and layout hashes directly from the binary, without relying on the digest structure. Attestations (`book/graph/mappings/system_profiles/attestations.json`) re-walk the logical content of the profiles—literals, anchors, op_table entries—and record them, along with references to vocab and tag layouts. CARTON’s manifest (`book/api/carton/CARTON.json`), finally, hashes the digests mapping itself to ensure that a client cannot silently pick up a partially updated file.

This structure means that the digests are not just a convenient summary; they are a checked contract tied both to the underlying blobs and to other mapping layers. If you change a blob or change your understanding of its shape, that will show up somewhere in this chain.

### Where the claim stops

There are clear limits to what is being claimed here.

First, these profiles are a narrow canonical set. The mapping does not claim to describe every system profile on the host; it deliberately focuses on three that the project has chosen as anchors. That choice is part of the world’s definition.

Second, the “bedrock” claim is about the compiled blobs and their decoded structure, not about fully tested runtime behavior. Apply gates on this host mean that you cannot always run these exact profiles end-to-end through the kernel. Where you can run related or recompiled versions (for example, a recompiled `bsd` or microprofiles inspired by these policies), runtime experiments are used and linked. Where you cannot, you treat the static IR as an accurate snapshot of what the kernel sees on disk, backed by hashes and structural checks, but you are explicit that this is not a runtime theorem.

Third, the contract is temporal and world-specific. If Apple ships a new `bsd` profile with a different op_table_hash or tag layout, the contract will detect that drift and demote status. At that point, older chapter-level claims about “what `sys:bsd` looks like” are no longer current; you will need to treat the profile as degraded until you have re-established evidence for the new version. The system is engineered to make that visible rather than to silently reinterpret “bedrock” to mean “whatever the current blob happens to be.”

---

## Recommendation

With all of this in place, it is reasonable to promote the three concepts to bedrock for this world.

The operation vocabulary is now clearly identified as “what this host’s libsandbox exports,” backed by dyld manifests, a disciplined harvest pipeline, alignment and digest cross-checks, and per-op coverage that separates structurally present operations from those you have examined at runtime. The claim it makes is modest but firm: for this world, these are the operations and filters that exist, and these are their numeric IDs.

The modern profile format and tag layouts have moved from “strongly suspected” to “contracted” for a particular subset of tags. Decoder-side inference from canonical blobs and compiler-side analysis of `libsandbox`’s emit paths tell the same story for those tags, and that story is now wired into canonical profile contracts and tag-layout metadata. Unknown tags and unmodeled format corners are left openly heuristic; the bedrock claim is about the covered layouts, not about everything.

The canonical system profiles are now treated as compiled objects with explicit contracts, rather than as vaguely understood exemplars. Their blobs are hash-checked, their structure is summarized in digests that are tightly constrained by tests and generators, and their status is allowed to degrade in a controlled way when contract fields change. Those digests feed directly into tag layouts, coverage mappings, CARTON indices, and attestations, which gives you a coherent picture of “what the OS ships” for this world.

Given that bedrock is defined here as “safe to treat as fixed inputs for this world, with explicit demotion paths if evidence drifts,” these three concepts now meet that bar. Downstream tools, CARTON clients, and written chapters can rely on them as given, while the manifest, contract, and demotion machinery you have put in place remains the route by which future changes or discoveries will be handled.
