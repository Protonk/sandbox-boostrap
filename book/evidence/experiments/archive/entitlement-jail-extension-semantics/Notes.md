- Initialized experiment scaffold (Plan/Report/Notes/out).
- Located EntitlementJail app at /Users/achyland/Desktop/entitlement-jail/EntitlementJail.app.
- Ran sandbox_extension update_file_rename_delta with external rename on a Desktop harness file; captured witness at book/evidence/experiments/entitlement-jail-extension-semantics/out/witnesses/ej_update_file_rename_delta.json.
- Witness sha256: 57c1a34e8b79985cb9b755de4005fe535b2a3ea7989dc78a6f2d0892897847cb.
- Command:
  ```
  EJ="/Users/achyland/Desktop/entitlement-jail/EntitlementJail.app/Contents/MacOS/entitlement-jail"
  old_path="/Users/achyland/Desktop/entitlement-jail-harness/ej_extension_semantics_old.txt"
  new_path="/Users/achyland/Desktop/entitlement-jail-harness/ej_extension_semantics_new.txt"
  mkdir -p "/Users/achyland/Desktop/entitlement-jail-harness"
  printf 'ej extension semantics\n' >"$old_path"
  rm -f "$new_path"
  "$EJ" xpc run --profile temporary_exception sandbox_extension \
    --op update_file_rename_delta --class com.apple.app-sandbox.read \
    --path "$old_path" --new-path "$new_path" --allow-unsafe-path --wait-for-external-rename \
    > book/evidence/experiments/entitlement-jail-extension-semantics/out/witnesses/ej_update_file_rename_delta.json &
  pid=$!
  sleep 1
  mv "$old_path" "$new_path"
  wait "$pid"
  ```
- CLI emitted high-concern warning for temporary_exception@base (temporary_exception_sbpl).
- Derived first-pass invariants and H1/H2 claims from the witness (out/invariants.json, out/claims.json).
- Ran deterministic negative control with destination preexisting (dest_preexisted) to force early harness exit; captured witness at book/evidence/experiments/entitlement-jail-extension-semantics/out/witnesses/ej_update_file_rename_delta_dest_exists.json.
- Witness sha256: 4e4d6a9409a0badf6a0e7c2538ef609031b635655af76701753e960413f37a9b.
- Command:
  ```
  EJ="/Users/achyland/Desktop/entitlement-jail/EntitlementJail.app/Contents/MacOS/entitlement-jail"
  old_path="/Users/achyland/Desktop/entitlement-jail-harness/ej_extension_semantics_old_exists.txt"
  new_path="/Users/achyland/Desktop/entitlement-jail-harness/ej_extension_semantics_new_exists.txt"
  mkdir -p "/Users/achyland/Desktop/entitlement-jail-harness"
  printf 'ej extension semantics\n' >"$old_path"
  printf 'preexisting\n' >"$new_path"
  "$EJ" xpc run --profile temporary_exception sandbox_extension \
    --op update_file_rename_delta --class com.apple.app-sandbox.read \
    --path "$old_path" --new-path "$new_path" --allow-unsafe-path \
    > book/evidence/experiments/entitlement-jail-extension-semantics/out/witnesses/ej_update_file_rename_delta_dest_exists.json
  ```
- Ran EntitlementJail evidence snapshot (bundle-evidence + verify-evidence); outputs under book/evidence/experiments/entitlement-jail-extension-semantics/out/evidence/entitlementjail.
- Command:
  ```
  EJ="/Users/achyland/Desktop/entitlement-jail/EntitlementJail.app/Contents/MacOS/entitlement-jail"
  out_dir="book/evidence/experiments/entitlement-jail-extension-semantics/out/evidence/entitlementjail"
  mkdir -p "$out_dir"
  "$EJ" bundle-evidence --out "$out_dir"
  "$EJ" verify-evidence > "$out_dir/verify-evidence.txt"
  ```
- Evidence shas: bundle_meta.json f41d9a90ab72f2e74e9476a3822e89753e0f9d98020512b94e3255d07a550d8d, verify-evidence.json 31884f09b7239b26a50684b0b7659f7da5ad2a3f80645ec477c27100ec3babe4, Evidence/manifest.json 43e76f19ca3674c3d3c6ad59ccffbeea1e57d215792355f815c6fdb447ed7778.
- Sanitized evidence bundle JSON/text to remove absolute app paths (app_root -> EntitlementJail.app).
- Updated invariants and claims to accept H3-H6, switch to JSON pointer surfaces, and record deny-attribution posture (out/invariants.json, out/claims.json).
