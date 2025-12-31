# entitlement-jail-extension-semantics: harnessed sandbox extension semantics

This is an EntitlementJail harness exercise: success is gated, phase-ordered, invariant-backed transitions, not narrative plausibility or rc-only outcomes.

## Purpose

Freeze EntitlementJail sandbox extension semantics into rerunnable, disk-backed evidence with strict phase ordering, pid/session continuity, and invariant proofs. The focus is on attribution (deny -> allow in a single durable session), binding (path vs inode), and maintenance calls (update_file* behavior), using the existing EntitlementJail harnesses without inventing new vocab or abstractions.

## Baseline & scope

- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Host scope only; do not generalize beyond this baseline.
- Primary fixture: EntitlementJail `sandbox_extension --op update_file_rename_delta` (single-session witness with phase markers, access checks, and rename/update probes).

## Expected artifacts

- Raw witness: `out/witnesses/ej_update_file_rename_delta.json`.
- Negative control witness: `out/witnesses/ej_update_file_rename_delta_dest_exists.json`.
- Derived invariants: `out/invariants.json`.
- Derived claim evaluations: `out/claims.json`.

## Portable rerun sketch (shape only)

Use `$HOME` so the run shape is portable; keep the Desktop target to preserve the deny/allow semantics. The `temporary_exception` profile is expected to warn as high concern because it enables `file-issue-extension` via a temporary exception SBPL entitlement.

```sh
EJ="${HOME}/Desktop/entitlement-jail/EntitlementJail.app/Contents/MacOS/entitlement-jail"
old_path="${HOME}/Desktop/entitlement-jail-harness/ej_extension_semantics_old.txt"
new_path="${HOME}/Desktop/entitlement-jail-harness/ej_extension_semantics_new.txt"
mkdir -p "${HOME}/Desktop/entitlement-jail-harness"
printf 'ej extension semantics\n' >"$old_path"
rm -f "$new_path"
"$EJ" xpc run --profile temporary_exception sandbox_extension \
  --op update_file_rename_delta --class com.apple.app-sandbox.read \
  --path "$old_path" --new-path "$new_path" --allow-unsafe-path --wait-for-external-rename \
  > book/experiments/entitlement-jail-extension-semantics/out/witnesses/ej_update_file_rename_delta.json &
pid=$!
sleep 1
mv "$old_path" "$new_path"
wait "$pid"
```

Negative control (destination preexists):

```sh
old_path="${HOME}/Desktop/entitlement-jail-harness/ej_extension_semantics_old_exists.txt"
new_path="${HOME}/Desktop/entitlement-jail-harness/ej_extension_semantics_new_exists.txt"
printf 'ej extension semantics\n' >"$old_path"
printf 'preexisting\n' >"$new_path"
"$EJ" xpc run --profile temporary_exception sandbox_extension \
  --op update_file_rename_delta --class com.apple.app-sandbox.read \
  --path "$old_path" --new-path "$new_path" --allow-unsafe-path \
  > book/experiments/entitlement-jail-extension-semantics/out/witnesses/ej_update_file_rename_delta_dest_exists.json
```

## Hypotheses and gates

### H1 — Intervention point: pre-consume deny is an operation-stage sandbox deny

- **Hypothesis:** A denied Desktop file read is denied at `open_read` before any sandbox extension consume occurs, and the denial manifests as `EPERM`.
- **Gate:**
  - `data.details.access_pre_consume_old_open_outcome == "deny"` and `data.details.access_pre_consume_old_open_errno == "1"`.
  - Phase ordering is explicit via `data.details.delta_old_open_transition` and the `access_pre_consume_*` vs `access_post_consume_*` field prefixes.
- **Disqualifiers:**
  - Missing pre-consume check or ambiguous ordering.
  - The witness cannot prove which process context performed the check (missing `data.details.pid` or `data.details.service_pid`).
- **Artifacts:** `out/witnesses/ej_update_file_rename_delta.json`, `out/invariants.json`, `out/claims.json`.

### H2 — Attribution: issue + consume flips deny->allow immediately in the same durable session

- **Hypothesis:** Under the entitlement-bearing service, `issue + consume` flips the same `open_read` from `EPERM` to success immediately, with continuity of process and durable session.
- **Gate:**
  - Pre-consume: `data.details.access_pre_consume_old_open_outcome == "deny"` with `data.details.access_pre_consume_old_open_errno == "1"`.
  - Post-consume: `data.details.access_post_consume_old_open_outcome == "allow"` for the same target.
  - Same process context: `data.details.pid == data.details.service_pid`.
  - Same durable session: `data.details.session_token` present.
  - Extension live: `data.details.consume_handle` present and `data.details.access_post_consume_old_open_outcome == "allow"`.
- **Disqualifiers:**
  - Post-check success not attributable to the same pid or session.
  - Success appears only after restart/relaunch/re-consume.
- **Artifacts:** `out/witnesses/ej_update_file_rename_delta.json`, `out/invariants.json`, `out/claims.json`.

### H3 — Binding: consumed grant behaves as path-scoped (does not follow inode across rename)

- **Hypothesis:** The consumed extension behaves as path-scoped: after an inode-preserving rename, access to the new path is denied again even though `st_dev` and `st_ino` did not change.
- **Gate:**
  - Rename premise: `data.details.rename_was_inode_preserving == "true"` and both `data.details.rename_same_dev == "true"` and `data.details.rename_same_inode == "true"` (backed by `data.details.stat_old_dev/stat_old_ino` and `data.details.stat_new_dev/stat_new_ino`).
  - Extension live across rename: `data.details.consume_handle` present and `data.details.access_post_consume_old_open_outcome == "allow"`.
  - Post-rename access check: `data.details.access_after_rename_new_open_outcome == "deny"`.
- **Disqualifiers:**
  - Rename premise cannot be proven (copy/replace, cross-device move, or missing invariants).
  - Extension-live continuity cannot be shown through rename and check.
- **Artifacts:** `out/witnesses/ej_update_file_rename_delta.json`, `out/invariants.json`, `out/claims.json`.

### H4 — Maintenance: sandbox_extension_update_file(path) retargets the live grant after rename

- **Hypothesis:** After rename breaks access on the new path, `sandbox_extension_update_file(path)` restores allow on the new path immediately without re-issue or re-consume.
- **Gate:**
  - Post-rename new-path `open_read = EPERM`: `data.details.access_after_rename_new_open_outcome == "deny"`.
  - `update_file(path)` recorded: `data.details.update_file_rc` and `data.details.update_file_errno` present (call recorded; decision still gated on access delta).
  - Post-update access check: `data.details.access_after_update_file_new_open_outcome == "allow"`.
  - pid/session continuity and extension-live continuity hold across deny -> update -> allow (`data.details.pid == data.details.service_pid`, `data.details.session_token` present, `data.details.consume_handle` present).
- **Disqualifiers:**
  - Missing post-update access check.
  - Allow appears only after a fresh issue/consume.
- **Artifacts:** `out/witnesses/ej_update_file_rename_delta.json`, `out/invariants.json`, `out/claims.json`.

### H5 — Return codes are not evidence: update_file_by_fileid can be rc==0 without access delta

- **Hypothesis:** `update_file_by_fileid` may return rc==0 while producing no observable access change, and non-actionable candidates remain non-actionable.
- **Gate:**
  - Candidate sweep is recorded: `data.details.update_by_fileid_candidate_count` with `data.details.update_by_fileid_candidate_*_name`.
  - For each candidate, witness records `data.details.update_by_fileid_<name>_rc`, `data.details.update_by_fileid_<name>_changed_access`, and `data.details.access_after_update_by_fileid_<name>_new_open_outcome`.
  - At least one candidate shows `rc==0` with `changed_access == "false"` (access delta remains absent).
  - Candidate provenance is recorded via payload fields (for example `data.details.update_by_fileid_st_dev_payload_u64` with `data.details.stat_old_dev`).
- **Disqualifiers:**
  - Missing post-call access checks or missing pid/session attribution.
  - Candidate provenance not recorded.
- **Artifacts:** `out/witnesses/ej_update_file_rename_delta.json`, `out/invariants.json`, `out/claims.json`.

### H6 — Harness integrity: early failures are classified as harness/protocol outcomes

- **Hypothesis:** When a run fails early (protocol violation, I/O error, precondition failure), the witness reports a distinct normalized outcome with always-present fields, not an ambiguous "child exited" result.
- **Gate:**
  - Negative-control witness has `result.normalized_outcome == "dest_preexisted"` and `data.details.dest_preexisted == "true"`.
  - Witness shape is complete (always-present envelope keys: `schema_version`, `kind`, `generated_at_unix_ms`, `result.*`, `data`, plus `data.details.pid` and `data.details.session_token`).
  - Outcome is distinct from access checks (`dest_preexisted` is not an `open_read` deny).
- **Disqualifiers:**
  - Negative control is not deterministic.
  - Witness shape is incomplete or missing classification fields.
- **Artifacts:** `out/witnesses/ej_update_file_rename_delta.json` (or a separate negative-control witness), `out/invariants.json`, `out/claims.json`.
