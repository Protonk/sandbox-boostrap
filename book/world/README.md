# World Baselines

This directory holds per-host world baselines. Each world lives in its own subdirectory (for example `sonoma-14.4.1-23E224-arm64/`) with a `world-baseline.json` that captures the host identity, SIP state, and pointers to the dyld manifest and other host-level knobs that influence decoding and runtime probes.

The `example-world/` directory is a template for creating a new world:

- `example-world/world-baseline.json` — fill in host fields, optional `world_id`, capture reason, and a pointer to the dyld manifest. Add runtime-impacting toggles such as `profile_format_variant`, `apply_gates`, and `tcc_state` as needed.
- `example-world/dyld-manifest.json` — list trimmed dyld slices (paths, byte sizes, SHA256 digests) and key symbol anchors used for vocab/encoder extraction. Hashing this manifest is the suggested way to derive `world_id`.
- `example-world/README.md` — quick instructions for copying the template and filling the placeholders.

How to add a world:
1) Copy `example-world/` to `book/world/<new-id>/`.
2) Extract the dyld slices you depend on (e.g., libsandbox, libsystem_sandbox) into that directory and record them in `dyld-manifest.json` with hashes and symbol offsets.
3) Compute a manifest hash and set `world_id` in `world-baseline.json` (when world IDs are in use), for example:
   - `python - <<'PY'\nimport hashlib, pathlib\np = pathlib.Path('book/world/<new-id>/dyld-manifest.json')\nprint(hashlib.sha256(p.read_bytes()).hexdigest()[:8])\nPY`
   - Suggested format: `<baseline-id>-dyld-<sha8>`
4) Populate `world-baseline.json` with host OS/build/kernel/arch/SIP and any runtime knobs you track.
5) Point generators at the new baseline and regenerate mappings and validation outputs for that world.

Treat `world-baseline.json` as immutable once published; regenerate downstream artifacts instead of editing an established baseline.
