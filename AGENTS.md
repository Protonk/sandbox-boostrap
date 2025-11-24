# AGENTS — Start Here
>This file’s sole purpose is to get an agent from zero context to the right map in one hop.
You just landed in a **synthetic textbook workspace** about the macOS Seatbelt/XNUSandbox. There is no app to build; everything here exists to read, decode, and explain sandbox policies.

## What this place is
- A knowledge substrate for a future textbook on the macOS sandbox.
- Runnable labs and tooling to compile, ingest, and dissect sandbox profiles.
- Guidance docs that define the model, vocabulary, and known drifts on modern macOS.

## First reads (do these before exploring code)
- `guidance/Orientation.md` — the high-level model (SBPL → compiled profiles → kernel decisions; platform vs per-process).
- `guidance/Concepts.md` — glossary of core entities (operations, filters, decisions, extensions, params, formats).
- `guidance/Appendix.md` — SBPL cheatsheet, binary profile format, operation/filter vocab, stacking notes.
- `guidance/Canon.md` — the approved external sources; use for research routing.
- `guidance/ERRATA.md` — macOS 14.x behavior gaps vs the model.

## Where things live
- `examples/` — runnable labs and probes (mach, network, containers, entitlements, extensions, params, metafilters) plus tooling (compile, disassemble, regex viz). Each folder has a `lessons.md` and sometimes a local `AGENTS.md`.
- `concepts/` — concept inventory and shared code (e.g., profile ingestion for modern and legacy blobs under `cross/profile-ingestion`).
- `guidance/` — the conceptual spine listed above; `guidance/sources/` holds per-source exegesis.
- `book/` — early chapter stubs intended to become the textbook proper.
- `profiles/` — real profiles to anchor the story (e.g., TextEdit App Sandbox).
- `history/` — modernization, explainer, and reset reports describing what changed and why.

## If your prompt is vague (“what is this project?”)
- Answer: it is a teaching/research substrate for the macOS sandbox, not a product. Your job is to read/ingest/describe, not to ship features.
- Navigate in this order: root `AGENTS.md` (this file) → `guidance/Orientation.md` → `guidance/Concepts.md` → skim `examples/README.md` to see the lab menu.

## If you need runnable entry points
- Start with `examples/sb/` or `examples/sbsnarf/` to compile a sample SBPL into a blob.
- Use `concepts/cross/profile-ingestion/ingestion.py` to parse modern/legacy blobs.
- For legacy format disassembly, see `examples/sbdis/`; for regex viz, `examples/re2dot/`.

## If you need external context
- Stay local unless instructed otherwise. If allowed, `guidance/Canon.md` tells you which external sources exist and how to use them; `guidance/sources/` holds local exegesis so you rarely need to leave the repo.