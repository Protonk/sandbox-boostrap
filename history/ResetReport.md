# Reset Report

## 1. Project Map
/
- AGENTS.md
- README
- guidance/
  - AGENTS.md
  - Appendix.md
  - Canon.md
  - Concepts.md
  - ERRATA.md
  - Orientation.md
  - Reading.md
  - sources/
    - APPLESANDBOXGUIDE/exegesis.md
    - BLAZAKIS2011/exegesis.md
    - BLAZAKIS2011/launchpad.md
    - HACKTRICKS_MACOSSANDBOX/exegesis.md
    - ROWESANDBOXING/exegesis.md
    - SANDBLASTER2016/exegesis.md
    - STATEOFTHESANDBOX2019/exegesis.md
    - WORMSLOOK2024/exegesis.md
    - WORMSLOOK2024/probe-ideas.md
  - reports/
- concepts/
  - README.md
  - CONCEPT_INVENTORY.md
  - __init__.py
  - cross/
    - __init__.py
    - profile-ingestion/
      - README.md
      - __init__.py
      - ingestion.py
      - smoke/test_profile_ingestion.py
    - profile_ingestion.py
- examples/
  - AGENTS.md
  - README.md
  - apple-scheme/Makefile
  - apple-scheme/apple-scheme-flat.md
  - apple-scheme/lessons.md
  - apple-scheme/run-demo.sh
  - containers-and-redirects/containers-and-redirects-flat.md
  - containers-and-redirects/containers_demo.swift
  - containers-and-redirects/lessons.md
  - entitlements-evolution/entitlements-evolution-flat.md
  - entitlements-evolution/entitlements_example.c
  - entitlements-evolution/lessons.md
  - extensions-dynamic/extensions-dynamic-flat.md
  - extensions-dynamic/extensions_demo.c
  - extensions-dynamic/lessons.md
  - extract_sbs/compile_profiles.py
  - extract_sbs/extract_sbs-flat.md
  - extract_sbs/run-demo.sh
  - libsandcall/Makefile
  - libsandcall/libsandcall-flat.md
  - libsandcall/lessons.md
  - libsandcall/run-demo.sh
  - mach-services/lessons.md
  - mach-services/mach-services-flat.md
  - mach-services/mach_client.c
  - mach-services/mach_server.c
  - metafilter-tests/lessons.md
  - metafilter-tests/metafilter-tests-flat.md
  - metafilter-tests/metafilter_demo.sh
  - network-filters/lessons.md
  - network-filters/network-filters-flat.md
  - network-filters/network_demo.c
  - platform-policy-checks/lessons.md
  - platform-policy-checks/platform-policy-checks-flat.md
  - platform-policy-checks/platform_policy.c
  - re2dot/lessons.md
  - re2dot/re2dot-flat.md
  - re2dot/re2dot.py
  - resnarf/resnarf-flat.md
  - resnarf/resnarf.py
  - sb/compile_sample.py
  - sb/lessons.md
  - sb/run-demo.sh
  - sb/sample.sb
  - sb/sb-flat.md
  - sbdis/find_operations.py
  - sbdis/lessons.md
  - sbdis/ops.txt
  - sbdis/redis.py
  - sbdis/run-demo.sh
  - sbdis/sb_format.txt
  - sbdis/sbdis-flat.md
  - sbdis/sbdis.py
  - sbpl-params/lessons.md
  - sbpl-params/params_demo.sh
  - sbpl-params/sbpl-params-flat.md
  - sbsnarf/lessons.md
  - sbsnarf/sbsnarf-flat.md
  - sbsnarf/sbsnarf.py
- book/
  - chapters/
    - chapter01-Introduction/README.md
    - chapter02-TextEdit/README.md
- profiles/
  - textedit/application.sb
  - textedit/container-notes.md
  - textedit/textedit-entitlements.plist
- history/
  - ConceptsReport.md
  - ExplainerGeneration.md
  - ModernizationReport.md
  - ResetReport.md (this file)
- .gitignore
- .DS_Store

## 2. Prompt and Response
Prompt: This project is not a traditional software project. Traverse the whole project and produce a report on the contents and your guess as to the aim. Don't give "next steps" or flag issues. Give me a report on what is here and where it seems to be going.

Response: **Project Aim**
- `README`: framing is a “synthetic textbook” on macOS security aimed at teaching a robot; the rest of the repo centers on Seatbelt/XNUSandbox (macOS sandbox) concepts, docs, and runnable probes.

**Guidance Layer**
- `guidance/Orientation.md`: high-level Seatbelt model (SBPL → TinyScheme → compiled profiles → kernel decisions; platform vs per-process stacking).
- `guidance/Appendix.md`: SBPL cheatsheet plus binary profile/graph reference, operation and filter vocab, and stacking notes.
- `guidance/Concepts.md`: glossary of core entities (operation, filter, decision, extensions, params, formats, vocab maps).
- `guidance/Canon.md`: curated external sources with summaries and how to use them; strong 2010–2019 focus.
- `guidance/ERRATA.md`: macOS 14.x divergences (sandbox_apply blocked without entitlement, sandbox-exec effectively dead, format detection quirks, paramized profiles).
- `guidance/Reading.md` and `guidance/AGENTS.md`: routers describing how agents/humans should traverse the guidance pack.

**Concept Layer & Shared Code**
- `concepts/CONCEPT_INVENTORY.md`: detailed inventory of Seatbelt concepts with status/epistemic tags; ties to cross-cutting axes (ingestion, graph construction, vocab, rendering).
- `concepts/cross/profile-ingestion/ingestion.py`: shared Python ingestion layer for compiled profiles; supports modern graph format and a legacy decision-tree format, exposing header parsing and section slicing (`ProfileBlob`, `ProfileHeader`, `ProfileSections`, format detection).
- `concepts/cross/profile_ingestion.py`: import shim for the dash-named package; `smoke/test_profile_ingestion.py` builds the sample sb profile and parses both modern and synthetic legacy blobs.
- `concepts/README.md`: explains the role of cross abstractions (ingestion, policy graph, vocab, rendering) meant to be shared across examples.

**Example Labs (`examples/`, mapped in `examples/AGENTS.md`)**
- Sandbox behavior probes: `entitlements-evolution` (signature/entitlement inputs), `extensions-dynamic` (extension tokens), `containers-and-redirects` (container paths/symlinks), `mach-services` (mach-lookup/register), `network-filters` (socket domains/types), `platform-policy-checks` (platform vs app policy), `metafilter-tests` (require-any/all/not), `sbpl-params` (SBPL parameters).
- Compilation and tooling: `apple-scheme` (sandbox_compile_file demo), `libsandcall` (compile/apply via libsandbox), `sbsnarf` (SBPL→blob CLI), `sb` (sample pipeline now using shared ingestion), `sbdis` (legacy decision-tree disassembler now using shared ingestion for headers), `resnarf` (extract regex blobs from legacy profiles), `re2dot` (AppleMatch regex to DOT), `extract_sbs` (compile system .sb profiles with params).
- Each directory has `lessons.md` (where present) and flattened snapshots (`*-flat.md`) showing contents and intent.

**History**
- `history/ModernizationReport.md`: summarizes modernization of examples for macOS 14.x and key observations (sandbox_exec demise, apply blocking, format shifts).
- `history/ExplainerGeneration.md`: notes on auditing/generating explainers and fixing extract_sbs CLI.
- `history/ConceptsReport.md`: changelog for the shared ingestion layer (modern and legacy formats) and refactors to use it.

**Book & Profiles**
- `book/chapters/chapter01-Introduction/README.md`: placeholder “Write me later.”
- `book/chapters/chapter02-TextEdit/README.md`: notes a TextEdit-themed chapter on profiles.
- `profiles/textedit/application.sb` and `profiles/textedit/textedit-entitlements.plist`: real App Sandbox profile and entitlements for TextEdit, plus `container-notes.md` noting its container root.

**Overall Trajectory**
- The repository is building a structured knowledge substrate and runnable labs around Apple’s Seatbelt sandbox: foundational docs → concept inventory → shared ingestion code → targeted examples/tooling → eventual textbook chapters anchored by real profiles (e.g., TextEdit). The focus is on decoding/understanding compiled sandbox policies and modern platform behavior rather than enforcing or shipping code.

## 3. guidance/sources Map
- APPLESANDBOXGUIDE/
  - exegesis.md: Summary of the Apple Sandbox Guide v1.0 focusing on SBPL operation taxonomy and user-visible policy surface (operations, filters, modifiers, quirks).
- BLAZAKIS2011/
  - exegesis.md: Reverse-engineering study of Snow Leopard Seatbelt pipeline from APIs through compiled decision trees and MAC hooks; maps operation/filter codes and stock profiles.
  - launchpad.md: Orientation plus symbol/structure inventory extracted from Blazakis’s paper for code-grepping and implementation alignment.
- HACKTRICKS_MACOSSANDBOX/
  - exegesis.md: Practitioner/offensive overview of macOS sandbox behavior, containers, entitlements, extension tokens, and observable bypass surfaces.
- ROWESANDBOXING/
  - exegesis.md: Implementation-oriented overview of macOS sandboxing lifecycle, SBPL, platform vs per-process policy, and MACF enforcement.
- SANDBLASTER2016/
  - exegesis.md: Analysis of the SandBlaster toolchain and reversed iOS profiles, extrapolating binary profile structure and SBPL semantics relevant to macOS.
- STATEOFTHESANDBOX2019/
  - exegesis.md: Empirical study of App Sandbox adoption and entitlement usage across macOS apps; high-level mechanism recap plus measurement findings.
- WORMSLOOK2024/
  - exegesis.md: Modern walkthrough of sandbox integration (containers, entitlements, secinit/libsandbox, Sandbox.kext, MACF hooks, extensions).
  - probe-ideas.md: Hypothesis set derived from WORMSLOOK2024, framed as testable probes for modern macOS/iOS behavior.

## 4. Proposed Root README
# sandbox-bootstrap (reset draft)

This repo is the seed of a synthetic textbook on macOS Seatbelt/XNUSandbox. The audience is “future me” and other agents who need a crisp, local-only substrate for understanding and explaining the sandbox. Nothing here enforces policy; everything here exists to decode, document, and teach.

## How to navigate
- Start with `guidance/` (Orientation, Concepts, Appendix, Canon, ERRATA) to align on the model, vocabulary, and known drifts.
- Use `concepts/` for the concept inventory and any shared code layers (e.g., the profile-ingestion helpers).
- Treat `examples/` as runnable labs: each folder is a focused probe or tool with a short `lessons.md`.
- `history/` captures modernization and refactor notes; check it before changing shared layers.
- `book/` holds draft chapter stubs; `profiles/` stores real profiles (e.g., TextEdit) to anchor the narrative.

## What exists today
- Guidance layer: stable orientation, glossary, appendix, canon, and errata for macOS 14.x observations.
- Concept layer: inventory with status/epistemic tags; shared ingestion code for modern and legacy profile formats.
- Labs/tooling: compilation probes (`apple-scheme`, `sbsnarf`), ingestion/disassembly (`sb`, `sbdis`, `resnarf`, `re2dot`), behavior probes (mach, network, containers, entitlements, extensions, params, metafilters, platform policy).
- Anchors: TextEdit App Sandbox profile and entitlements; chapter stubs noting intended coverage.

## Working rules
- Always align changes with `guidance/AGENTS.md` and the concept inventory; avoid silent drift from the documented model.
- Keep parsing, graph construction, vocab mapping, and rendering concerns separated.
- Note macOS version and format assumptions; add to `ERRATA.md` when observations diverge from the current model.
- Prefer extending shared layers (`concepts/cross/`) over duplicating parsing or vocab logic inside examples.

## Near-term intent
- Flesh out book chapters using the labs and profiles as concrete anchors.
- Expand vocab mapping and rendering layers so decoded profiles read like SBPL.
- Keep modernization notes current as macOS evolves; treat this repo as the canonical local substrate for Seatbelt reasoning.

## 5. Reasoning Notes
- Read the root and `guidance/AGENTS.md` instructions, then enumerated the project tree and key files via `find` to capture structure accurately.
- Inspected `guidance/sources/*/*.md` headers to summarize each source’s intent and content for the sources map.
- Reused the prior prompt/response verbatim to satisfy the conversation snapshot requirement.
- Composed the proposed README to orient a future maintainer: purpose, navigation, current assets, working rules, and intent, grounded in existing docs and shared code.
- Ensured Section 1 stays purely structural, Section 3 includes light content summaries as requested, and overall formatting remains terse and readable for later reference.
