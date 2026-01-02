# looking-glass — PROFILE_TOOLCHAIN (SBPL ↔ compiled blobs ↔ structure)

This bundle describes the profile-focused toolchain in SANDBOX_LORE: how SBPL is compiled into host-format blobs, how those blobs are decoded/inspected, and what kinds of structural claims the repo treats as stable enough to anchor mappings.

Scope: profile bytes and structural decoding. It does **not** cover runtime application/allow/deny semantics (see `RUNTIME_AND_WITNESS_TOOLCHAIN.md`).

Baseline anchor: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

## 1) Two representations, two failure modes

Seatbelt policy exists in two forms:
- **SBPL**: a Scheme-like source language (human authored, compilation target).
- **Compiled blobs**: the host’s binary profile format (what the system actually applies/evaluates).

SANDBOX_LORE’s profile tooling is mostly about ensuring you can:
- compile SBPL into the host’s blob format, and
- decode blobs into stable structural objects (headers, op tables, tags, literal pools),
without pretending that structure alone implies semantics.

## 2) The unified entrypoint: `book.api.profile`

The repo’s supported “profile byte work” surface is `book.api.profile` (Python API + CLI).

Common commands:

### Compile SBPL -> blob
```sh
python -m book.api.profile compile <profile.sb> --out <out_path.sb.bin>
```

### Decode/inspect a compiled blob
```sh
python -m book.api.profile decode dump <blob.sb.bin> --summary
python -m book.api.profile inspect <blob.sb.bin> --out <out_path.json>
```

### Op-table views (structural)
```sh
python -m book.api.profile op-table <profile_or_blob> ...
```

Interpretation discipline:
- Successful compile/decode is **structural** evidence (stage `compile`).
- A decoded node/tag layout is not a behavioral claim until paired with runtime evidence.

## 3) The vocabulary spine: ops and filters

Profiles reference operations and filters by host-specific IDs. SANDBOX_LORE pins that vocabulary as bedrock:

- `book/graph/mappings/vocab/ops.json`
- `book/graph/mappings/vocab/filters.json`

Everything else (decoding, tag layouts, runtime coverage) is keyed off these names/IDs.

## 4) Canonical system profiles as structural anchors

SANDBOX_LORE curates a small set of system profiles as “structural anchors.” These serve as:
- regression detectors (drift should be loud),
- mapping inputs (tag layouts, literal pools, op-table patterns),
- and stable reference points for later semantic witness work.

The canonical contract surface lives under:
- `book/graph/mappings/system_profiles/digests.json`

That file encodes:
- which canonical profiles exist (for example `sys:bsd`, `sys:airlock`),
- which fields are treated as contract fields (hashes/lengths/tag counts/world_id),
- and operational status for each canonical profile.

Design partner takeaway: when someone says “this tag layout is stable,” they usually mean “it is stable across the canonical anchor corpus for this world, and guardrails enforce it.”

## 5) What the repo tries to decode (structurally)

The decoding surface aims to produce stable, comparable structure:
- headers (format variants and versioning signals),
- op pointer tables (operation ID -> entry point),
- node arrays / tags (layout + payload shapes),
- pooled literals and regex data.

Some fields remain intentionally under-interpreted until they have stronger witness coverage.

## 6) Common structural workflows (what people actually do)

### 6.1 “What changed when I edited SBPL?”

Compile two SBPL variants and compare:
- op-table entries,
- tag counts/layouts,
- literal pool deltas,
without assuming behavior changed in the same way.

### 6.2 “What does a shipped profile look like?”

Decode a canonical system profile blob and treat the decoded summary as a structural fingerprint:
- it constrains what the compiler emits and what the evaluator expects,
- but does not imply it is apply-able or runnable on this host (apply gating is separate).

### 6.3 “Is this blob/profile from the right world?”

Check the artifact’s `metadata.world_id` (or contract world binding) matches the repo baseline.

If it doesn’t, treat it as a different world; don’t mix.

## 7) Guardrails and regen rules (profile-adjacent)

Profile work frequently feeds mapping generators and CARTON. As a result:
- avoid hand-editing generated/shared artifacts,
- prefer the repo’s supported entrypoints (compile/decode via `book.api.profile`, mappings promotion via `book/graph/mappings/run_promotion.py`),
- and use `make -C book test` as the drift detector.

