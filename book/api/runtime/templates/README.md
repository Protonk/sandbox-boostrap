# runtime templates

These are copy-and-edit templates for adding a new runtime probe family.
They are not referenced by the registry index and are safe to edit locally.

Suggested workflow:
1) Use the plan builder to generate plan/registry data (preferred):
   `python -m book.api.runtime plan-build --template <id> --out book/experiments/<exp> --overwrite`
2) If you are not using the plan builder, copy `plan.json` into your experiment as `book/experiments/<exp>/plan.json`.
3) Copy `probes.json` + `profiles.json` into `book/experiments/<exp>/registry/`.
4) Update the registry index (`book/api/runtime/registry/index.json`) to point at the new registry.
5) Run `python -m book.api.runtime registry-lint --registry <id>` and `plan-lint` before running.

Available templates:
- `runtime-adversarial` (plan + registry for adversarial runtime probes).
- `vfs-canonicalization` (path-family probes for VFS canonicalization).
