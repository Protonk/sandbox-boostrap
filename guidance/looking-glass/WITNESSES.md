# looking-glass — WITNESSES (boundary objects & controls)

This bundle lists SANDBOX_LORE’s current **boundary objects**: small witness sets that constrain what can be true on this host baseline. It is designed for a *design partner* who can’t inspect the repo directly.

When a question spans layers (SBPL ↔ compiled graphs ↔ runtime ↔ kernel ↔ environment), don’t answer it by storytelling. **Pick the witness that should decide it**, then propose the smallest move that strengthens or reuses that witness.

Baseline anchor: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Sonoma 14.4.1, Apple Silicon, SIP enabled).

## How to use this

- Treat each witness as a **decision primitive**: “If this holds, we can safely design X; if not, we need Y next.”
- Prefer **controls** over narrative: passing neighbors, one-variable toggles, and stage-labeled outcomes.
- Keep “how we know” explicit: dyld extraction + compiled structure + runtime probes + Ghidra/KC (when available) are meant to interlock.

## Evidence braid (syncretic, by design)

- **Dyld**: extracted `libsandbox` / `libsystem_sandbox` slices + manifests, used to harvest stable tables.
- **Compiled structure**: decode headers/op-tables/nodes/literals and summarize canonical blobs.
- **Runtime**: plan-based runs that emit committed bundles (`artifact_index.json`) and `promotion_packet.json`, with stage (`compile|apply|bootstrap|operation`) and lane (`scenario|baseline|oracle`) labeling.
- **Ghidra/KC**: xrefs and evaluator-shape constraints (including *negative results* that constrain design).
- **Lifecycle**: sandboxed app harnesses + contract-shaped outputs (future end-to-end stories).

---

## Core witness examples (use these in design conversations)

### 1) Dyld vocab spine (Operations + Filters)
- **Decides:** what ops/filters (names+IDs) exist on this host.
- **Evidence braid:** dyld extraction → harvested tables → published vocab mappings; pinned by a dyld slice manifest.
- **Mapping paths (bedrock):** `book/evidence/graph/mappings/vocab/ops.json`, `book/evidence/graph/mappings/vocab/filters.json`, `book/evidence/graph/mappings/vocab/ops_coverage.json`
- **Controls:** count/order invariants; spot-check a few IDs.
- **Confounder:** scope (naming ≠ behavior).
- **Ask user for:** ops/filters counts + 3 sample entries + dyld manifest excerpt (`book/world/<world_name>/dyld/manifest.json` or `book/evidence/graph/mappings/dyld-libs/manifest.json`).

### 2) Canonical compiled-profile anchors (blobs → stable digests)
- **Decides:** what the curated system profiles look like structurally (op_count/op-table/tags/literals).
- **Evidence braid:** canonical blobs → digests/static checks/attestations → consumed by other mappings/tools.
- **Mapping paths (bedrock):** `book/evidence/graph/mappings/system_profiles/digests.json`, `book/evidence/graph/mappings/system_profiles/static_checks.json`, `book/evidence/graph/mappings/system_profiles/attestations.json`
- **Controls:** stable identity + “re-decode yields same summary.”
- **Confounder:** stage (apply-gated ≠ runnable).
- **Ask user for:** one excerpt from `book/evidence/graph/mappings/system_profiles/digests.json` for `sys:bsd` and `sys:airlock`.

### 3) Tag layout island (bounded subset we can decode)
- **Decides:** which tags have reliable record layouts for literal/regex operands.
- **Evidence braid:** decode canonical profiles → tag exemplars → published layout map + guardrails.
- **Mapping path (bedrock):** `book/evidence/graph/mappings/tag_layouts/tag_layouts.json`
- **Controls:** “layout sanity” excerpt on canonical corpus.
- **Confounder:** scope (layout ≠ semantic meaning).
- **Ask user for:** covered tags + record size + one exemplar decode (or a small excerpt from `book/evidence/graph/mappings/tag_layouts/tag_layouts.json`).

### 4) Op-table bucket signatures (synthetic SBPL probes)
- **Decides:** how bucket patterns shift under small SBPL changes (structural fingerprints).
- **Evidence braid:** SBPL microprofiles → compile → decode → bucket patterns + per-entry signatures.
- **Controls:** one-edit deltas; single-op baselines.
- **Confounder:** scope (buckets are opaque labels until witnessed otherwise).
- **Ask user for:** one “ops-set → bucket pattern” row + one signature snippet.

### 5) Apply-gate corpus (attach-time `EPERM` ≠ denial)
- **Decides:** whether `EPERM` is an apply/attach gate vs a PolicyGraph decision.
- **Evidence braid:** wrapper stage markers (`compile`/`apply`) + minimized failing vs passing neighbor + bounded log window + (when available) Ghidra xrefs into sandbox kext/kernelcache slices.
- **Controls:** compile succeeds but apply fails; bounded log window; neighbor control.
- **Confounder:** surround (harness identity / parent environment).
- **Ask user for:** one witness row (stage+errno) + the log line + the kext-xref summary.

### 6) VFS canonicalization suite (path literals vs runtime reality)
- **Decides:** which path spellings actually match for specific alias families (notably `/tmp` ↔ `/private/tmp`).
- **Evidence braid:** tri-profile design (alias-only/canon-only/both) + structural decodes + runtime results + `path_witnesses.json` (FD-reported spellings when available) to keep canonicalization visible without ad hoc parsing.
- **Controls:** the tri-profile matrix (it is the control).
- **Confounder:** scope (family/operation specific).
- **Ask user for:** the suite’s “what canonicalizes, what doesn’t” summary paragraph.

### 7) Runtime “golden families” (narrow, but semantic)
- **Decides:** do we have repeatable decision-stage allow/deny cases?
- **Evidence braid:** expectation matrices + stage-aware runs + normalized events. Current mapped runtime coverage includes: `file-read*`, `file-write*`, `network-outbound`, `mach-lookup`, `file-read-xattr`, `file-write-xattr`, `darwin-notification-post`, `distributed-notification-post`, `process-info-pidinfo`, `signal`, `sysctl-read`, `iokit-open-service`.
- **Controls:** `baseline` lane control + `scenario` lane control under a clean channel (for example `launchd_clean`).
- **Confounder:** stage/lane confusions (apply/bootstrap failures, nested sandboxes), plus path normalization.
- **Ask user for:** `promotion_packet.json` `promotability` excerpt + one `runtime_events.normalized.json` snippet for a single op.

### 8) Field2 closure (bounded unknowns + kernel constraints)
- **Decides:** whether the u16 payload slot yields a clean semantic map (or a hi/lo split).
- **Evidence braid:** inventories over canonical/probe blobs + Ghidra evaluator work showing raw-u16 handling + explicit u16-role declarations per tag.
- **Controls:** unknown set scoped to tags whose u16 role is “filter vocab id.”
- **Confounder:** scope (unknown ≠ meaningless; it means “not yet mapped”).
- **Ask user for:** closure summary + one snippet of the “raw-u16” kernel observation.

### 9) Lifecycle scaffold (PolicyWitness / App Sandbox harness)
- **Decides:** do we have an instrumented way to ask App Sandbox + entitlement questions without freehanding?
- **Evidence braid:** PolicyWitness.app at `book/tools/witness/PolicyWitness.app` (sandboxed XPC services) + host-side CLI + contract fixtures under `book/tools/witness/fixtures/contract/` + structured outputs meant to host future end-to-end witnesses.
- **Controls:** contract fixtures (CLI help + JSON shape pinned).
- **Confounder:** surround/stack (TCC, hardened runtime, SIP can dominate).
- **Ask user for:** fixture excerpt (help or sample observer JSON) + one probe output schema snippet.

---

## Summary table (pick the boundary object first; the table is the last stop)

| Witness | Decides | Evidence braid | Best control | Primary confounder | Ask user for |
|---|---|---|---|---|---|
| Dyld vocab spine | ops/filters names+IDs | dyld → tables → mappings | count/order invariants | scope | counts + 3 entries + dyld manifest |
| Canonical profile anchors | structural “what ships” | blobs → digests/attestations | re-decode stability | stage | one digest excerpt |
| Tag layout island | decodable tag subset | decode → layouts → guardrails | exemplar decode | scope | covered tags + exemplar |
| Op-table buckets | bucket shifts/signatures | SBPL → compile → signatures | one-edit deltas | scope | one bucket-pattern row |
| Apply-gate corpus | attach-time EPERM | markers + logs + kext xrefs | failing+neighbor | surround/stage | witness row + log line |
| VFS canonicalization | path matching reality | tri-profiles + runtime | tri-profile matrix | scope | suite summary paragraph |
| Runtime golden families | repeatable semantics | matrix + stage/lane + promotion | baseline + clean channel | stage/lane | promotion_packet + events snippet |
| Field2 closure | bounded unknowns | inventories + Ghidra eval | role-scoped unknown set | scope | closure summary excerpt |
| Lifecycle scaffold | App Sandbox + entitlements | PolicyWitness + fixtures | contract fixtures | surround/stack | fixture + schema snippet |
