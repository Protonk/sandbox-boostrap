# AGENTS.md

You are inside the Seatbelt textbook workspace. Use this file as a fast nav map to the major hubs; it does not prescribe workflows.

- **graph/ (contracts + generator)**
  - `graph/Sources/main.swift` — Swift contracts and CLI that emit JSON artifacts.
  - `graph/Package.swift` — SwiftPM manifest.
  - `graph/concepts/` — concept inventory, handoff notes, validation docs, generated JSON (`concepts.json`, `concept_text_map.json`, `validation/strategies.json`).
  - `graph/regions/` — stub `text_regions.json`.

- **examples/**
  - One folder per example (extensions-dynamic, mach-services, sbpl-params, etc.). Generated index: `examples/examples.json`.

- **chapters/**
  - Chapter content and plans (e.g., `chapter01-Introduction/`, `chapter03-TextEdit/`, `chapter06-Example.app/`).

- **profiles/**
  - SBPL profile sources (e.g., TextEdit profiles, tools, and outputs).

- **api/**
  - API planning notes (`api/PLAN.md`, etc.).

