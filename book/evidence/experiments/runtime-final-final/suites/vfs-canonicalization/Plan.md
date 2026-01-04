# Plan (follow-ups)

This plan is scoped to `world_id sonoma-14.4.1-23E224-arm64-dyld-a3a840f9` and turns the remaining “open questions” into concrete, host-bound experiments that extend this suite without changing its purpose.

Baseline reading for intent and current results:

- `book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/Report.md`
- `status/learnings/merged_vfs_report.md`

## Goal

Convert three broad uncertainties into checkable, promotable evidence on this host:

1. What spelling variations collapse during pathname handling vs. remain policy-relevant here?
2. When do “different spellings” actually refer to the same object identity (and when don’t they)?
3. How fragile are vnode→path spellings under hardlinking and rename/unlink races, and how should we treat that fragility as a witness limitation?

## Experiment 1 — Spelling variations and component-gate match domains

### Question

For `file-read*` / `file-write*` probes on this host:

1. Which spelling variations are eliminated by pathname processing / filesystem equivalence before SBPL matching becomes relevant?
2. For traversal-time component gates (observed as deny-side `file-read-metadata` / `file-read-data` on a directory component), does the effective match domain behave like the alias spelling, the resolved spelling, or something else?

This specifically aims to answer a fact question that the current suite results strongly motivate:

- “For these component gates, does allowing the *pre-resolution* spelling ever work, or do we need to allow the *post-resolution* spelling?”

### Design (A) — Component gate domain mapping (alias vs resolved component)

Add paired “component-allow” variants for the existing component-gate families, keeping everything else unchanged:

- `/etc` component gate (currently flips with `(allow file-read-metadata (literal "/etc"))`)
  - add `vfs_etc_both_plus_metadata_private_etc` using `(allow file-read-metadata (literal "/private/etc"))`
  - compare which profile flips `/etc/hosts` on this host
- `/var` component gate (currently flips with `(allow file-read-metadata (literal "/var"))`)
  - add `vfs_var_tmp_both_plus_metadata_private_var` using `(allow file-read-metadata (literal "/private/var"))`
  - compare which profile flips `/var/tmp/vfs_canon_probe` on this host
- `openat(2)` leafname directory gate (currently flips with `(allow file-read-data (literal "/private/tmp"))`)
  - add `vfs_private_tmp_only_openat_dir_allowed_tmp_alias` using `(allow file-read-data (literal "/tmp"))`
  - compare which profile flips the leafname `openat` probes on this host

Evidence interpretation rule for this sub-experiment:

- Treat the deny-side witness line (for example `deny(1) file-read-metadata /etc`) as the primary indicator of which component gate is failing; treat allow-side FD spellings as evidence only for allowed attempts.

### Design (B) — Purely lexical variations vs filesystem equivalence

Split this axis into two buckets so results remain interpretable:

**Bucket 1: likely lexical normalization (path processing)**

- repeated slashes (`/private/tmp//probe`)
- `./` components (`/private/tmp/./probe`)

**Bucket 2: filesystem equivalence (depends on volume features)**

- case differences (e.g. `Probe` vs `probe`)
- Unicode normalization differences (composed vs decomposed spellings of the same name)

Trailing slashes are not “purely lexical” for non-directories. If we test trailing slashes, do it only with:

- a directory fixture target, and
- an open mode that isolates “open directory” semantics (e.g., `O_DIRECTORY` in a dedicated open-only probe),

so we do not accidentally measure `ENOTDIR` / `EISDIR` behavior instead of sandbox behavior.

### Mechanics (profiles, probes, fixtures)

- Keep the operation surface stable (`file-read*`, `file-write*`) to avoid changing the suite’s semantic guardrails.
- Use a new dedicated fixture family under `/private/tmp` (avoid reusing `/tmp/foo`).
- For each new family, use the tri-profile pattern:
  - “baseline spelling only”
  - “variant spelling only”
  - “both”
- For the `..` / symlink-component axis, continue to use the existing oracle guardrail (`SANDBOX_CHECK_CANONICAL`) as a negative control: “raw allow but canonical deny” is expected when the input is not already canonical.

### Evidence and outputs

- Allow-side: `out/<run_id>/path_witnesses.json` (compare `requested_path` vs `observed_path*`)
- Deny-side: `out/derived/deny_log_witnesses.json` (identify whether the denial is a component gate like `file-read-metadata` on a directory)
- Summary join: `out/derived/runtime_results.json`

### Known confounders to control

- Separate “filesystem equivalence” from “policy behavior”:
  - If the filesystem does not resolve two spellings to the same object, sandbox results are not informative for SBPL matching.
  - If the filesystem *does* resolve them to the same object, compare `requested_path` to `observed_path` as a witness for the stored/reconstructed spelling the kernel prefers.
- Case/Unicode behavior is volume-feature-dependent (APFS case-insensitive and normalization-insensitive behavior can collapse distinctions before SBPL matching becomes relevant). If results are ambiguous, rerun on a purpose-created APFS disk image with known settings and record mount identity.

## Experiment 2 — Make object identity a first-class join spine

### Question

When the suite observes “alias spelling and canonical spelling both allow,” is that because they reach the same underlying object (same vnode identity), or because two different objects happen to be reachable and allowed?

### Design

- Run the suite with identity emission enabled:
  - `SANDBOX_LORE_FD_IDENTITY=1`
  - keep deny observer enabled:
    - `SANDBOX_LORE_WITNESS_OBSERVER=1 WITNESS_OBSERVER_MODE=show`
- Extend identity emission to include a better hardlink identity when available:
  - keep `(st_dev, st_ino)` from `fstat(2)`
  - add `linkid` via `getattrlist` (`ATTR_CMNEXT_LINKID`) when supported (best-effort, optional)
  - keep mount identity via `fstatfs(2)` (best-effort, optional)
- Extend derived summaries to surface identity fields (best-effort, optional) and make missingness explicit:
  - in `out/derived/runtime_results.json`, carry `fd_identity` when present and include an explicit missing reason when not present (for example `fd_identity_source: missing_on_deny`)
- Add a small set of identity assertions in the suite report:
  - “these two requests hit the same identity under these profiles” (include `(st_dev, st_ino)` and `linkid` when available)

### Evidence and outputs

- Raw: `out/<run_id>/runtime_results.json` and `out/<run_id>/path_witnesses.json` should contain identity records for successful opens when enabled.
- Derived: `out/derived/runtime_results.json` should carry identity forward for review.

### Acceptance criteria

- For each family where we currently claim “two spellings behave like one target,” there is at least one allow-side witness showing the same identity across both spellings in the sandboxed lane.

## Experiment 3 — Hardlink and rename/unlink stress tests for vnode→path spellings

### Question

How often does vnode→path reconstruction produce “a different but valid spelling,” and can it drift under rename/unlink even when the FD identity is stable?

### Design

- Hardlink axis:
  - create two hardlinks to the same inode under a controlled directory (fixtures)
  - open via each name under the same profile and compare:
    - `fd_identity` (should match)
    - `observed_path` (may differ)
- Rename/unlink axis:
  - add a small dedicated native probe (or extend an existing one) that:
    - opens a file (FD exists)
    - renames/unlinks it after open
    - calls `F_GETPATH` again
  - record whether `observed_path` changes while identity stays fixed

Practical expectations (do not treat as “mysterious failures”):

- path reconstruction can fail or vary under churn; treat transient errors and drift as witness behavior, not as sandbox semantics
- if available, use a second reconstruction route as a cross-check:
  - `fsgetpath(2)` from `(fsid, obj_id)` (hardlink ambiguity is expected for inode-only identity)
  - prefer using `linkid` when present for the hardlink axis, and explicitly record when path reconstruction is ambiguous

### Evidence and outputs

- `out/<run_id>/path_witnesses.json` (must include both spellings and identity)
- suite report: explicitly list this as “limits of path witnesses,” not as a sandbox semantic claim

### Acceptance criteria

- At least one stable, reproducible demonstration that vnode identity can stay fixed while `F_GETPATH` spelling is not a unique “truth,” with artifacts committed in the suite’s run bundle.
