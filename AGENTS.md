# AGENTS — Start Here
>This file’s sole purpose is to get an agent from zero context to the right map in one hop.
You just landed in a **synthetic textbook workspace** about the macOS Seatbelt sandbox. There is no app to build; everything here exists to read, decode, and explain sandbox policies.

## What this place is
- A knowledge substrate for a future textbook on the macOS sandbox.
- Runnable labs and tooling to compile, ingest, and dissect sandbox profiles.
- Guidance docs that define the model, vocabulary, and known drifts on modern macOS.

## Where things live
- `concepts/` — concept inventory and shared code (e.g., profile ingestion for modern and legacy blobs under `cross/profile-ingestion`).
- `substrate/` — the conceptual spine listed above; `substrate/exegesis/` holds per-source exegesis.
- `book/` — the book, including code examples and profiles

## If your prompt is vague (“what is this project?”)
- Answer: it is a teaching/research substrate for the macOS sandbox, not a product. Your job is to read/ingest/describe, not to ship features.
- Navigate in this order: root `AGENTS.md` (this file) → `substrate/AGENTS.md`
