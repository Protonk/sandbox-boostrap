# VFS Canonicalization (runtime-backed, non-semantic)

Stable VFS canonicalization mappings live under `book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/`. This directory hosts the generator and documentation.

Scope:
- Host: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`
- Evidence: promotable **decision-stage** runtime bundles produced by `book/api/runtime` (clean channel), plus their promotion receipts.
- Domain: path spellings and kernel-reported FD paths (`F_GETPATH` and `F_GETPATH_NOFIRMLINK`) for the focused `book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/` suite.

Non-goals:
- This is not a general VFS theory or a cross-version claim.
- This does not claim that any observed path spelling is the literal Seatbelt matched; it records what the kernel reports for an FD and keeps the attribution bounded.

## Files

- `book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/packet_set.json` – ordered input packet list for this mapping slice.
- `book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/promotion_receipt.json` – audit receipt for packet selection (used vs rejected).
- `book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/path_canonicalization_map.json` – the generated mapping output for this world.

## Regeneration

From repo root:

```sh
python book/integration/carton/mappings/vfs_canonicalization/generate_path_canonicalization_map.py
```

This generator is the only supported writer for `promotion_receipt.json` and `path_canonicalization_map.json`.
