# Path Resolution, Vnode Path Spellings, and SBPL Path Filters (Sonoma baseline)

## Scope (non-negotiable)

This report is scoped to one fixed host baseline world:

- `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`

It is intentionally narrow. It is a portable lesson about a common *class* of problems (path-based sandbox rules interacting with path resolution and path reconstruction), but every concrete claim about behavior is bounded to this host and to the operation surface exercised by the repo’s runtime suite:

- primary ops: `file-read*`, `file-write*`
- supporting gatepoints observed in this suite: `file-read-metadata`, `file-read-data`

If you want raw discussion prompts/citations, use `status/learnings/vfs_links.md`. For the authoritative, host-bound experiment narrative and committed run bundles, use `book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/Report.md` (the directory name is local; the conceptual framing in this report is “lookup-time resolution + vnode path spellings”).

## The core issue: policy authored over spellings, enforcement over objects (plus traversal)

A pathname string is a *spelling*. The kernel’s Virtual File System (VFS) turns that spelling into an object (a vnode) via name lookup: traversing mounts, interpreting `.`/`..`, following symlinks, and applying macOS-specific directory translations (for example, System/Data volume presentation).

SBPL profiles are authored over *strings* (literal spellings, prefixes, subpaths), but runtime behavior can be dominated by:

- lookup-time resolution (where the spelling can change before the final object is reached),
- per-component gate checks during traversal (directories and symlink components can be separately authorized),
- enforcement points where only a vnode is available (so the original user spelling is not necessarily a stable input to the policy engine).

This creates three “path spellings” that can legitimately diverge:

- `requested_path`: what userland passed to the syscall (caller-controlled)
- a decision-time spelling or component spelling: what the sandbox associates with the particular check it is denying/allowing (kernel-derived)
- `observed_path*`: kernel-reconstructed spellings for a successfully opened FD (`F_GETPATH`, and optionally `F_GETPATH_NOFIRMLINK`)

Critical constraint: **denied attempts often have no sandboxed FD**, so `F_GETPATH*` cannot witness deny-time spellings. If you want deny-side spelling evidence, you need a separate, sandbox-originated witness channel (for example, denial log lines).

## Evidence surfaces (what to trust, and what not to overclaim)

### 1) Structural (static) evidence

Structural decoding can tell you what anchors/literals exist in the compiled PolicyGraph structure for a profile. This is useful for “does the string exist in structure?” but it does not tell you which spelling will be semantically live at runtime on this host.

### 2) Allow-side witnesses (FD exists)

When the sandboxed probe successfully opens a file, it can emit kernel-reported spellings for that FD:

- `observed_path` via `F_GETPATH`
- `observed_path_nofirmlink` via `F_GETPATH_NOFIRMLINK` (when supported)
- optional `fd_identity` (best-effort object identity when enabled: `st_dev`, `st_ino`, mount identity via `fstatfs(2)`)

Important limitations:

- vnode→path reconstruction can be non-unique (hardlinks / multiple names)
- vnode→path reconstruction can be sensitive to rename/unlink races
- vnode→path spellings can be process-relative (procroot-style effects)

Treat `F_GETPATH*` as a witness, not as proof of “the internal compare key.”

### 3) Deny-side witnesses (no FD exists)

When an operation is denied before the process receives an FD, `F_GETPATH*` cannot be used. On this host, the repo’s best deny-side spelling witness is a sandbox-originated denial log line captured during probe execution. The runtime harness can optionally collect these lines, and the suite derives them into:

- `book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/out/derived/deny_log_witnesses.json`

This is still a diagnostic string witness (not a formal proof of the internal compare key), but it is much closer to the decision pipeline than any post hoc reconstruction.

### 4) `sandbox_check*` callouts (oracle lane)

The runtime harness can optionally call `sandbox_check_by_audit_token` alongside syscall probes. On this host, `SANDBOX_CHECK_CANONICAL` behaves as a **strictness flag** (“reject if the supplied path is not already canonical,” notably symlink components and `..` traversal), not as “canonicalize then check.” Treat it as a guardrail axis, not a path-discovery mechanism.

Also note: flags like `NO_REPORT` are observability/overhead knobs (suppresses expensive violation reporting). They should not be treated as a mechanism for obtaining a structured “post-canonicalization path” return value.

## Host-bounded findings on this world (runtime-backed)

These findings are bounded to the suite’s fixtures, the operation surface above, and committed bundles referenced by `book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/out/LATEST`.

### A) `/tmp/*` requests behave as if `/private/tmp/*` is the semantically live spelling

In the tri-profile pattern:

- alias-only (`/tmp/*` literals) denies attempts spelled as both `/tmp/*` and `/private/tmp/*`
- canonical-only (`/private/tmp/*` literals) allows attempts spelled as both `/tmp/*` and `/private/tmp/*`
- both-spellings matches canonical-only (control)

When a sandboxed FD exists for an allowed `/tmp/foo` request, `F_GETPATH` reports `/private/tmp/foo`. This is consistent with lookup-time resolution of `/tmp` into `/private/tmp` on this host, and it is the smallest “runtime confounder” model that fits the observed allow/deny outcomes for this family.

### B) One FD can have multiple kernel spellings; Data-volume spellings are not effective SBPL literal keys in this suite

For allowed opens, the suite often observes both:

- `F_GETPATH` in a firmlink-translated namespace (for example `/private/tmp/...`)
- `F_GETPATH_NOFIRMLINK` in a Data-volume namespace (for example `/System/Volumes/Data/private/tmp/...`)

However, for the firmlink-focused probes in this suite:

- a Data-only literal profile denies even a Data-volume-spelled request, and
- a `/private/...`-only literal profile can allow a Data-volume-spelled request.

Bounded interpretation: for these probes on this host, path evaluation behaves as if it is occurring in the firmlink-translated namespace, and Data-volume spellings should be treated as diagnostic witnesses rather than safe primary SBPL literals.

### C) Traversal-component denials explain “both spellings allowed but still denied”

The suite contains multiple cases where allowing the final file literal is not sufficient until a component traversal gate is satisfied (as witnessed by deny-side logs):

- `/etc/hosts` can be denied with `file-read-metadata /etc` even when both `/etc/hosts` and `/private/etc/hosts` are allowed as `file-read*` literals; adding only `(allow file-read-metadata (literal "/etc"))` flips it to allow.
- `/var/tmp/...` can be denied with `file-read-metadata /var` even when both `/var/tmp/...` and `/private/var/tmp/...` are allowed as `file-read*` literals; adding only `(allow file-read-metadata (literal "/var"))` flips it to allow.
- an intermediate symlink-in-path request can be denied with `file-read-metadata` on the symlink component directory; adding only that literal flips it to allow.

Bounded interpretation: these are component-level traversal checks, not “final file literal mismatch” failures. They are consistent with lookup-stage enforcement being decomposed into multiple checks on intermediate components.

### D) Syscall surface matters: `openat(2)` via `dirfd` can introduce extra authorization points

The suite’s `openat(2)` probes show a clean split:

- An `openat` leafname pattern (`open(parent_dir)` then `openat(dirfd, leaf)`) is denied under a profile that allows only the file literal `/private/tmp/foo`, with a deny-side witness `file-read-data /private/tmp`.
- A dedicated profile that adds only `(allow file-read-data (literal "/private/tmp"))` flips the same leafname `openat` probes to allow.
- A root-relative `openat` variant (pre-open `"/"` outside the sandbox apply, then `openat(rootfd, "tmp/foo")`) matches the `open(2)` results.

Bounded interpretation: “open the same file” is not a single authorization surface; decomposing the operation can add separately-authorized directory opens.

## Practical takeaways (portable, but examples are host-bound)

- Do not assume “two spellings that resolve to the same file” are interchangeable in SBPL. Prove it with tri-profiles on the host.
- Treat `/System/Volumes/Data/...` spellings as diagnostic (kernel witnesses) unless you have direct host-specific evidence that they are effective SBPL match keys.
- Expect component traversal gates (`file-read-metadata`) to matter when symlinks or directory aliases are present; allow the component explicitly if deny-side witnesses show it.
- Model syscall shape: `open(2)` vs `openat(2)` via a separately-opened `dirfd` can require different allows, even for the same target file.

## Repo-native workflow for experiments (portable recipe)

Use the runtime plan system and run through the clean channel so results are promotable and comparable:

- `python -m book.api.runtime run --plan book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/plan.json --channel launchd_clean --out book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/out`

To capture deny-side witnesses during a run, enable observer capture:

- `SANDBOX_LORE_WITNESS_OBSERVER=1 WITNESS_OBSERVER_MODE=show python -m book.api.runtime run ...`

Then derive the suite’s reviewable summaries:

- `PYTHONPATH=. python book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/derive_outputs.py`

Use `out/derived/runtime_results.json`, `out/derived/deny_log_witnesses.json`, and the run-scoped `out/<run_id>/path_witnesses.json` as the stable evidence interface. Treat raw stdout/stderr as debugging detail only.

## Mapping slice (`vfs_canonicalization`)

The repo maintains a CARTON mapping slice derived from runtime promotion packets:

- `book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/path_canonicalization_map.json`

This slice is intentionally conservative: it requires allow-side witness records and it refuses to infer behavior from denials (no sandboxed FD witness). Deny-side behavior is tracked separately via the deny-log witness artifacts above.

## Open questions (good next experiments)

1. **Lexical normalization beyond symlinks/firmlinks:** repeated slashes, trailing slashes, case, Unicode normalization. Keep volume feature flags in mind: filesystem behavior can collapse distinctions before SBPL string matching becomes relevant.
2. **Use `fd_identity` as a join spine everywhere:** verify whether alias and canonical spellings consistently hit the same `(st_dev, st_ino)` for the families where they appear interchangeable.
3. **Hardlink and rename stress tests:** measure how often `F_GETPATH` spellings drift under rename/unlink, and whether deny-side logs behave differently.
