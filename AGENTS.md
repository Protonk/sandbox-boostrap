# AGENTS — Start Here
>This file’s sole purpose is to get an agent from zero context to the right map in one hop.
You just landed in a **synthetic textbook workspace** about the macOS Seatbelt/XNUSandbox. There is no app to build; everything here exists to read, decode, and explain sandbox policies.

## What this place is
- A knowledge substrate for a future textbook on the macOS sandbox.
- Runnable labs and tooling to compile, ingest, and dissect sandbox profiles.
- Guidance docs that define the model, vocabulary, and known drifts on modern macOS.

## Where things live
- `examples/` — runnable labs and probes (mach, network, containers, entitlements, extensions, params, metafilters) plus tooling (compile, disassemble, regex viz). Each folder has a `lessons.md` and sometimes a local `AGENTS.md`.
- `concepts/` — concept inventory and shared code (e.g., profile ingestion for modern and legacy blobs under `cross/profile-ingestion`).
- `substrate/` — the conceptual spine listed above; `substrate/sources/` holds per-source exegesis.
- `book/` — early chapter stubs intended to become the textbook proper.
- `profiles/` — real profiles to anchor the story (e.g., TextEdit App Sandbox).

## If your prompt is vague (“what is this project?”)
- Answer: it is a teaching/research substrate for the macOS sandbox, not a product. Your job is to read/ingest/describe, not to ship features.
- Navigate in this order: root `AGENTS.md` (this file) → `substrate/Orientation.md` → `substrate/Concepts.md` → skim `examples/README.md` to see the lab menu.