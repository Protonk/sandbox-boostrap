# Path Resolution, Vnode Path Spelling, and SBPL Path Filters (Sonoma baseline)

## Scope (non-negotiable)

This report is scoped to the fixed host baseline world:

- `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`

It focuses on the filesystem operations used by the repo’s canonical path-family probes (`file-read*`, `file-write*`) and the path families covered by the focused VFS-canonicalization suite. It is not a general macOS or UNIX theory, and it does not claim universal Seatbelt semantics outside this baseline.

If you want the raw notes, citations, and discussion prompts that fed this report, use `status/learnings/vfs_links.md`. For the repo’s authoritative, host-bound experiment narrative, use `book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/Report.md`.

## The core subtlety: one object, many spellings

The kernel’s Virtual File System (VFS) layer turns a *path string* into an *object* (a vnode) via name lookup. Two distinct mechanisms then create “path spelling surprises” for sandbox work:

1. **Name lookup / path resolution effects** (before you get an FD):
   - Following symlinks (classic example: `/tmp` → `/private/tmp`).
   - Traversing mounts and other filesystem redirections.
   - On modern macOS, traversing the System/Data split presentation (firmlink-style translation).

2. **Vnode → path reconstruction effects** (after you have an FD):
   - Once you successfully open a file, you hold an FD that refers to a vnode; the FD does not inherently preserve the caller’s original spelling.
   - The kernel can reconstruct a printable path spelling for that vnode/FD, and multiple “valid” spellings can exist (for example, firmlink-translated vs “no firmlink” spellings).

SANDBOX_LORE historically called the combined phenomenon “VFS canonicalization.” That name is project-local; the more precise teaching framing is “path resolution + path reconstruction,” with the operational question being: *which spelling is the sandbox effectively comparing against on this host for a given operation and path family?*

## Why SBPL path filters are sensitive to this

SBPL path filters are written against strings (literal spellings, prefixes, subpaths). The compiled PolicyGraph structure preserves those spellings as anchors/literals; the structure does not automatically “collapse” aliases. Runtime enforcement, however, happens against the resolved object identity (vnode) and/or some kernel-derived spelling of that identity.

Operationally, that produces the central mismatch class this repo cares about:

- **Static:** “My profile mentions `/tmp/foo`.”
- **Runtime:** “The request targets a vnode whose reconstructed spelling lives in `/private/tmp/foo`.”
- **Outcome:** A profile that only embeds the alias spelling can fail, while a profile that embeds the canonical spelling succeeds.

This is why path families can dominate runtime outcomes even when the rest of the policy and harness are stable: if a spelling never reaches the match domain, it is effectively “dead” for enforcement on that host.

## Evidence surfaces in SANDBOX_LORE (what to trust, and what not to overclaim)

This repo separates **structure** from **runtime evidence**, and it treats path spelling as a confounder unless backed by committed artifacts.

### 1) Structural (static) evidence

Structural decoding tells you what anchors/literals the compiled PolicyGraph contains for a given SBPL profile. In the VFS-canonicalization suite, alias and canonical spellings remain distinct in structure: the graph does not collapse them.

Use the derived decode outputs produced by the suite (see the suite report for the specific artifacts it derives and guards).

### 2) Runtime bundles and promotability

Runtime evidence is produced by `book/api/runtime` and committed as run-scoped bundles (`out/<run_id>/...` with an `artifact_index.json` commit barrier). Decision-stage evidence is only promotable when run through the clean channel (`launchd_clean`) and the bundle passes the runtime contract’s gating.

This matters because “apply-stage failures” (for example `EPERM`) are usually staging/harness confounders, not policy denials. Keep stage/lane discipline when interpreting results.

### 3) Path witnesses (`path_witnesses.json`)

To study path spelling, the runtime service emits a dedicated IR: `path_witnesses.json` (see `book/api/runtime/SPEC.md`). Each record joins:

- `requested_path` (what the probe asked for),
- `observed_path` (kernel-reported FD spelling, usually via `F_GETPATH`, when an FD exists),
- `observed_path_nofirmlink` (alternate spelling via `F_GETPATH_NOFIRMLINK`, when available),
- a conservative `normalized_path` join key,
- and small canonicalization flags (alias pair, no-firmlink differs).

Important limits:

- **Denied opens produce no FD**, so they produce no FD-path witness. The mapping generators in this repo refuse to infer canonicalization from denials.
- A kernel “FD path spelling” is **not a proof** of the literal Seatbelt compared against; it is an observational witness of what the kernel reported for the opened object.

### 4) The non-semantic mapping slice (`vfs_canonicalization`)

The repo maintains a CARTON mapping slice derived from runtime promotion packets:

- `book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/path_canonicalization_map.json`

This mapping is intentionally conservative:

- Only uses decision-stage promotable packets when available (clean channel).
- Can fall back to baseline-only witnesses when promotability is unavailable, but still requires actual witness records.
- Refuses to infer from denied probes (no FD, no witness).

Treat it as “bounded observations of path spellings” for this world, not as a global semantic rule.

## Host-bounded findings (what is “mapped” vs “partial”)

The focused VFS-canonicalization suite exists because the `/tmp` family was a repeat confounder in runtime work on this host.

On this baseline, the suite’s summary is:

- **Mapped:** For the suite’s `file-read*`/`file-write*` probes, `/tmp/*` requests are observed (for successful opens) in the `/private/tmp/*` family, and runtime outcomes align with “the semantically live spelling is `/private/tmp/*`” for that family in this suite.
- **Mapped:** For the firmlink spelling probes in the suite, the harness often observes a firmlink-translated spelling (`F_GETPATH`) and a no-firmlink spelling (`F_GETPATH_NOFIRMLINK`) for the same FD; the suite’s *effective* behavior still tracks the `/private/tmp/*` family for the operations it exercises.
- **Partial / under exploration:** `/var/tmp` and `/etc` alias behavior, and “intermediate symlink path” behavior remain explicitly bounded and not promoted as broad invariants in the suite report.

When writing new claims, keep them bounded to the exact operations, paths, and harness used by the committed bundle(s).

## A practical experiment playbook (using repo-native tooling)

This section is a concrete recipe for extending what the suite already does, using the same evidence discipline.

### Step 1: Choose a path family + op surface

Pick one “alias family” to isolate at a time (symlink alias, firmlink spelling, mount alias, etc.), and keep the operation surface fixed (start with `file-read*`/`file-write*` because the harness already emits path witnesses for these).

Define:

- alias spelling(s),
- canonical spelling(s) you suspect,
- a single target file per spelling (keep it minimal).

### Step 2: Use the tri-profile pattern

For each family, use three minimal profiles:

- alias-only (mentions only the alias spelling),
- canonical-only,
- both.

This is the smallest structure that can separate “string-only hypothesis” from “resolution/reconstruction hypothesis.”

### Step 3: Run with bundle discipline (decision-stage when possible)

Use the runtime plan system and run through the clean channel so the result is promotable and comparable:

- `python -m book.api.runtime run --plan ... --channel launchd_clean --out ...`

Then derive the suite’s outputs (runtime summaries + decode summaries) and treat the derived outputs as the stable, reviewable interface.

### Step 4: Join structure ↔ runtime via witnesses

For each probe:

- compare the profile’s literal/anchor presence (structural decode),
- compare the runtime outcome (allow/deny),
- and compare `requested_path` vs `observed_path` / `observed_path_nofirmlink` when an FD exists.

If alias-only fails while canonical-only succeeds and witnesses show alias→canonical spelling shifts, classify it as a resolution/reconstruction confounder for that family on this host (bounded to that operation surface).

### Step 5: Handle denied attempts explicitly (no FD witness)

Because denied opens produce no FD, you need a separate witness route if you want “decision-time spelling” on denies. The best candidate to integrate is a **sandbox decision log witness** (for example, via SBPL `(debug deny)`), clearly labeled as “decision-log path spelling” (not FD-derived).

If you add this channel, keep it separate from `path_witnesses.json` semantics and avoid claiming it is the internal compare string; treat it as a decision-time string witness that can still be wrong/ambiguous in edge cases.

## Where to extend next (high-value questions turned into experiments)

The following open questions are actionable: they can be answered by small, instrumented experiments on this host, producing promotable evidence.

1. **`sandbox_check` “canonical” vs “raw” behavior:** The runtime harness already records `seatbelt-callout` markers that include `canonicalization: raw|canonical`. Determine whether “canonical” is purely lexical normalization, filesystem-backed resolution (symlink/firmlink), or a mix, by comparing callout decisions against actual syscall outcomes and FD witnesses for the same target.

2. **Decision reporting on denies:** If `sandbox_check*` can return a report (when `no_report=false`), test whether it includes a canonicalized path spelling on denies, and whether that spelling aligns with `F_GETPATH` or `F_GETPATH_NOFIRMLINK` when a corresponding allow case exists.

3. **New witness channel for denies:** Integrate `(debug deny)` (or equivalent) into the runtime harness as a first-class artifact, then teach the derive step to emit a “deny-path witness” IR that can be joined to probe rows (without pretending it is FD-based).

4. **Lexical normalization axes beyond symlink/firmlink:** Use controlled fixtures to probe whether the effective match domain collapses `.`/`..`, repeated slashes, trailing slashes, case differences, and Unicode normalization differences. Keep each axis isolated so the witness is interpretable.

## Minimal witness record (copy/paste template)

When writing up a new claim, keep it short, checkable, and host-scoped:

```text
claim:
  world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5
  status: ok|partial|brittle|blocked
  stage: compile|apply|bootstrap|operation
  lane: scenario|baseline|oracle (runtime only)
  command: <exact command or plan/scenario id>
  evidence:
    - <repo-relative path to committed bundle / promotion_packet.json / derived outputs>
  limits: <one line about what this does NOT prove>
```

