# Trace compatibility (Frida)

This note freezes the compatibility surface for the Frida trace “product” in `book/api/frida/`.

## Compatibility inputs (non-negotiable)

1. **Run directory contract**
   - A “Frida run directory” is a directory containing:
     - `meta.json`
     - `events.jsonl`
   - Tools may add derived artifacts (index/export/validation reports), but `meta.json` + `events.jsonl` remain the stable inputs.

2. **Hook payload shapes**
   - Existing Frida agent `send()` payload objects (the JSON objects emitted by hook scripts via `send({...})`) must remain representable by the trace product.
   - When the event stream is versioned/normalized, hook payloads must be preserved **without semantic transformation** (wrapping/embedding is allowed; field loss/renaming is not).

## Why this exists

The repo has multiple capture workflows (generic spawn/attach and EntitlementJail attach-first). We want to evolve the event stream into a versioned, headless, machine-checkable trace product without breaking the ability to consume:

- legacy runs already captured on this host baseline
- existing hook scripts and their `send()` payload shapes

See `book/api/frida/TRACE_PRODUCT_DECISIONS.md` for the headless invariants and the v1 envelope decisions.

