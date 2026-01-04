# extensions-dynamic probe notes

- world_id: sonoma-14.4.1-23E224-arm64-dyld-a3a840f9
- executable: book/api/lifecycle_probes/build/extensions_demo
- command: book/api/lifecycle_probes/build/extensions_demo
- result: blocked (exit 0), token_issued=false

- captured_at: 2025-12-18T20:30:25.512499+00:00

## stdout
```text
Sandbox extension demo targeting: /private/var/db/ConfigurationProfiles
Expect issuance to fail without entitlements; focus on the API steps.

open("/private/var/db/ConfigurationProfiles") -> success (fd=3)
sandbox_extension_issue_file failed errno=1 (Operation not permitted)
On systems without the right entitlements, issuance is denied by design. Skipping consume/release.

Extensions act as a third dimension: platform policy ∧ process policy ∧ active extensions.
Tokens map directly to `(extension ...)` filters compiled into the policy graph.
```

## stderr
```text

```
