# entitlement-jail-extension-semantics

## Purpose

Lock in EntitlementJail sandbox extension semantics as phase-ordered, invariant-backed witnesses on this host baseline. The focus is on deny -> allow attribution in a durable session, path binding across rename, and maintenance semantics for update calls.

## Baseline & scope

- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- This experiment consumes EntitlementJail harness outputs only; it does not introduce new ops/filters or global abstractions.

## Artifacts

Expected outputs (repo-relative):

- `book/experiments/entitlement-jail-extension-semantics/out/witnesses/ej_update_file_rename_delta.json`
- `book/experiments/entitlement-jail-extension-semantics/out/witnesses/ej_update_file_rename_delta_dest_exists.json`
- `book/experiments/entitlement-jail-extension-semantics/out/invariants.json`
- `book/experiments/entitlement-jail-extension-semantics/out/claims.json`
- `book/experiments/entitlement-jail-extension-semantics/out/evidence/entitlementjail/` (evidence bundle snapshot)

## Evidence & artifacts

Captured a single-session EntitlementJail witness using `sandbox_extension --op update_file_rename_delta` on a Desktop target with an external rename, plus a deterministic negative-control run that violates the destination precondition (`dest_preexisted`). An EntitlementJail evidence bundle snapshot is also included. The raw witnesses and derived evaluations are in:

- `book/experiments/entitlement-jail-extension-semantics/out/witnesses/ej_update_file_rename_delta.json`
- `book/experiments/entitlement-jail-extension-semantics/out/witnesses/ej_update_file_rename_delta_dest_exists.json`
- `book/experiments/entitlement-jail-extension-semantics/out/invariants.json`
- `book/experiments/entitlement-jail-extension-semantics/out/claims.json`
- `book/experiments/entitlement-jail-extension-semantics/out/evidence/entitlementjail/` (sanitized to remove absolute host paths)

Current evaluation (operation stage, scenario lane):
- H1 accepted (mapped): pre-consume `open_read` denied with `EPERM` and phase ordering is explicit in the witness fields.
- H2 accepted (mapped): deny -> allow transition occurs in the same pid/session with a live extension handle.
- H3 accepted (mapped): inode-preserving rename denies the new path while the extension remains live (path-scoped behavior).
- H4 accepted (mapped): `update_file(path)` retargets access on the new path without re-issue/consume.
- H5 accepted (mapped): `update_file_by_fileid` yields `rc==0` with no access delta for at least one candidate (st_dev).
- H6 accepted (mapped): negative-control run terminates early with `normalized_outcome=dest_preexisted` and a complete witness shape.
Attribution posture: no deny evidence captured; `EPERM` is treated as a permission-shaped outcome (not upgraded to a Seatbelt/App Sandbox denial).

## EJ identity & evidence bundle

Primary witness service identity:
- `service_bundle_id`: `com.yourteam.entitlement-jail.ProbeService_temporary_exception`
- `service_name`: `ProbeService_temporary_exception`
- `service_version`: `2.0.0`
- `service_build`: `2`

Evidence bundle snapshot (sanitized, repo-relative):
- `book/experiments/entitlement-jail-extension-semantics/out/evidence/entitlementjail/bundle_meta.json` (sha256 `f41d9a90ab72f2e74e9476a3822e89753e0f9d98020512b94e3255d07a550d8d`)
- `book/experiments/entitlement-jail-extension-semantics/out/evidence/entitlementjail/verify-evidence.json` (sha256 `31884f09b7239b26a50684b0b7659f7da5ad2a3f80645ec477c27100ec3babe4`)
- `book/experiments/entitlement-jail-extension-semantics/out/evidence/entitlementjail/Evidence/manifest.json` (sha256 `43e76f19ca3674c3d3c6ad59ccffbeea1e57d215792355f815c6fdb447ed7778`)

## Portable rerun sketch (shape only)

The `temporary_exception` profile is expected to warn as high concern because it enables `file-issue-extension` via a temporary exception SBPL entitlement.

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

## Dispersal-ready statements

- H1: world_id `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`; pre-consume Desktop `open_read` is denied with `EPERM` before any consume phase; witness sha256 `57c1a34e8b79985cb9b755de4005fe535b2a3ea7989dc78a6f2d0892897847cb`; pointers `/data/details/old_path`, `/data/details/access_pre_consume_old_open_outcome`, `/data/details/access_pre_consume_old_open_errno`, `/data/details/delta_old_open_transition`. Attribution: no deny evidence captured; treat `EPERM` as permission-shaped outcome.
- H2: world_id `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`; issue+consume flips `open_read` from deny to allow in the same pid/session with a live extension; witness sha256 `57c1a34e8b79985cb9b755de4005fe535b2a3ea7989dc78a6f2d0892897847cb`; pointers `/data/details/access_post_consume_old_open_outcome`, `/data/details/pid`, `/data/details/service_pid`, `/data/details/session_token`, `/data/details/consume_handle`.
- H3: world_id `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`; inode-preserving rename denies the new path while the extension remains live (path-scoped behavior); witness sha256 `57c1a34e8b79985cb9b755de4005fe535b2a3ea7989dc78a6f2d0892897847cb`; pointers `/data/details/rename_was_inode_preserving`, `/data/details/rename_same_dev`, `/data/details/rename_same_inode`, `/data/details/access_after_rename_new_open_outcome`, `/data/details/consume_handle`. Attribution: no deny evidence captured; treat `EPERM` as permission-shaped outcome.
- H4: world_id `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`; `sandbox_extension_update_file(path)` retargets access to the new path immediately without re-issue/consume; witness sha256 `57c1a34e8b79985cb9b755de4005fe535b2a3ea7989dc78a6f2d0892897847cb`; pointers `/data/details/access_after_rename_new_open_outcome`, `/data/details/update_file_rc`, `/data/details/access_after_update_file_new_open_outcome`, `/data/details/consume_handle`.
- H5: world_id `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`; `update_file_by_fileid` can return `rc==0` without an access delta for the `st_dev` candidate; witness sha256 `57c1a34e8b79985cb9b755de4005fe535b2a3ea7989dc78a6f2d0892897847cb`; pointers `/data/details/update_by_fileid_st_dev_rc`, `/data/details/update_by_fileid_st_dev_changed_access`, `/data/details/access_after_update_by_fileid_st_dev_new_open_outcome`, `/data/details/update_by_fileid_candidate_0_name`.
- H6: world_id `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`; destination-preexists negative control yields a distinct harness outcome (`result.normalized_outcome=dest_preexisted`) with full witness shape; witness sha256 `4e4d6a9409a0badf6a0e7c2538ef609031b635655af76701753e960413f37a9b`; pointers `/schema_version`, `/kind`, `/generated_at_unix_ms`, `/result/normalized_outcome`, `/result/ok`, `/result/rc`, `/data`, `/data/details/dest_preexisted`.

## Status

- Status: **ok** (H1-H6 accepted on the current host baseline).

## Blockers / risks

- Desktop access preconditions may vary across host configuration; attribution depends on explicit phase ordering + continuity fields in the witness.
- No sandbox-log attachment was captured; `EPERM` is treated as an access outcome, not proof of a Seatbelt deny.

## Next steps

- Optional: re-run with `--capture-sandbox-logs` if you want explicit deny attribution attached to the witness.
