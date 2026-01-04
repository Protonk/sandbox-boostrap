# World Baselines

This directory holds per-host world baselines. Each world lives in its own subdirectory (for example `sonoma-14.4.1-23E224-arm64/`) with `world.json` plus optional dyld manifest data used for vocab/encoder extraction.

World registry:
- `book/world/registry.json` lists known worlds and their `world.json` paths. This is the preferred entrypoint for tools that accept a world name or world_id.

The `example-world/` directory is a template for creating a new world. It is **not** a real baseline; its fields are intentionally null/empty so it cannot be mistaken for host evidence.

- `example-world/world.json` — template baseline record. Populate `world_id`, host fields, capture reason, and runtime-impacting toggles such as `profile_format_variant`, `apply_gates`, and `tcc_state`.
- `example-world/dyld/manifest.json` — template dyld manifest (empty). For a real world, list trimmed dyld slices (paths, byte sizes, SHA256 digests) and key symbol anchors used for vocab/encoder extraction.

Hashing the dyld manifest is the suggested way to derive `world_id`. Use the raw file bytes (no reformatting) and take the first eight hex digits of the SHA256 digest, appended to the baseline ID as `<baseline>-dyld-<sha8>`. Example (matches the Sonoma world in this repo):

```sh
python - <<'PY'
import hashlib, pathlib
manifest = pathlib.Path("book/world/sonoma-14.4.1-23E224-arm64/dyld/manifest.json")
h = hashlib.sha256(manifest.read_bytes()).hexdigest()
print(f"{h} -> {h[:8]}")
PY
```

Treat `world.json` as immutable once published; regenerate downstream artifacts instead of editing an established baseline.
