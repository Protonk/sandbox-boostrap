# Explainer generation and audit

This pass stitched the example suite together and audited the didactic explainers against code and core guidance:

- Generated flat snapshots for each `examples/` subdirectory to capture manifests and full contents.
- Reviewed lessons against `guidance/Orientation.md`, `guidance/Appendix.md`, and `guidance/Concepts.md` to verify claims about operations/filters, platform vs process policy, extensions, params, Mach, and network behavior.
- Added missing explainers for apple-scheme, libsandcall, re2dot, and sbsnarf; clarified existing ones with caveats about entitlements, SIP/platform policy, bootstrap namespace, and extension issuance limits.
- Corrected the `extract_sbs` harness to call `sandbox_compile_file` with the proper error buffer signature and cleaned its CLI/options.

Purpose: keep a lightweight log of the explainer generation/audit step so future edits can see what was validated and why.
