# Experiments

## 1. What an experiment is

In this project, an experiment is a small, concrete unit of work that ties claims about the macOS sandbox on this host to observable behavior.

Experiments exist to test specific questions or tensions, produce rerunnable interactions with the host, and leave behind evidence that can be checked, decoded, and reused. They are the bridge between the textbook’s concepts and what actually happens on the fixed Sonoma machine captured in `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (single source of truth for host metadata).

An experiment is not just a code snippet, a story, or a design sketch. It is a defined question, a way of exercising the system, and a record of what happened.

---

## 2. What a good experiment looks like

A good experiment has a clear shape and limited ambition:

* **Focused question**
  It is built around a narrow, explicit question (or a small cluster of closely related questions) about how Seatbelt or related machinery behaves.

* **Anchored in concepts**
  It states which project concepts it is exercising or clarifying (for example: operations, filters, policy graphs, containers, entitlements) using the canonical vocabularies in `book/graph/mappings/vocab/{ops,filters}.json` and the project’s concept inventory—no invented op/filter names.

* **Small but informative**
  It uses the simplest setup that can shed light on the question: a minimal test program, a small SBPL fragment, a focused decode, rather than a sprawling scenario.

* **Bounded context**
  It assumes a specific host state and notes any important preconditions (OS version, relevant configuration) that must hold for the results to make sense.

* **Repeatable and extendable**
  It can be rerun under the same conditions, and another agent can extend it (vary a parameter, add a case) without rebuilding everything from scratch.

---

## 3. Documentation expectations

An experiment should be documented so that another agent can understand it and extend it without additional explanation. Each experiment uses the required scaffold: `Plan.md`, `Report.md`, `Notes.md`, and an `out/` directory for artifacts.

When an experiment is archived (moved under `book/experiments/archive/`), its `out/` directory is intentionally denuded/removed, and the scaffold is retained as historical provenance only.

Each experiment should capture, somewhere:

* **Question and motivation**
  What the experiment is trying to find out, and why this question matters (for example, a confusion or gap in the existing concepts or state).

* **Context and environment**
  The host and OS context the experiment is intended for (reference `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`), and any key preconditions that affect behavior.

* **What was done**
  The essential steps: what was run or changed, in what order, and with what key parameters or inputs.

* **What was observed**
  The important outcomes from one or more runs: successes, failures, denials, errors, unexpected no-ops, or notable artifacts. Failures (EPERM/apply gates/decoder errors) are first-class observations and must be recorded, not omitted.

* **How it is currently interpreted**
  How these observations bear on the original question and on the relevant concepts, including the current level of confidence or status (`ok`, `partial`, `brittle`, `blocked`). Status is part of the meaning; do not upgrade it without evidence.

* **Open questions**
  Any remaining uncertainties or obvious follow-ups that would make the picture clearer.

The goal is a short, honest chain from question → actions → observations → interpretation, with enough detail that another agent can pick up the thread.

---

## 4. Experiment life-cycle

Experiments move through a simple life-cycle as they are created, refined, and integrated into the book.

* **Creation**
  An experiment is introduced to address a specific question or tension. At this stage, the question, scope, and intended link to concepts are sketched, and an initial way to exercise the system is defined.

* **Active iteration**
  The experiment is run and adjusted in short cycles. Different runs (including failures and dead ends) are recorded, and the interpretation is refined as more evidence accumulates. The status may change as the picture becomes clearer or more complicated.

* **Stability**
  Over time, the experiment reaches a steady state: the setup is well-understood, key behaviors are reproducible on the host, and the relationship to the concept inventory is reasonably stable. Documentation is cleaned up so that the current best reading is easy to see while past attempts remain accessible.

* **Promotion or supersession**
  Stable experiments often produce outputs (artifacts, tools, or distilled insights) that are useful beyond the experiment itself. When that happens, the experiment should clearly mark which outputs appear stable and broadly reusable, and suggest that they be used as shared references in the wider book. Any artifact promoted into `book/graph/mappings/*` must carry host metadata and have a guardrail test (e.g., in `book/tests/`). If a newer experiment replaces or sharpens an older one, that relationship should be noted so that readers can follow the chain.

* **Archival**
  Once an experiment’s useful outputs have been promoted into shared artifacts (`book/graph/mappings/**`, `book/tools/**`, etc.) and the experiment directory is no longer a live dependency surface, the experiment may be migrated to `book/experiments/archive/`. Archived experiments are “dead”: keep only `Report.md`, `Notes.md` (optionally `Plan.md`) plus a curated `Examples.md` with small excerpts. Remove large dumps and runnable wrappers so agents do not treat `archive/` as a place to mine for live tooling. See `book/experiments/archive/AGENTS.md`.

Across this life-cycle, experiments remain the primary link between the project’s claims and the fixed host. Their job is to accumulate reliable, inspectable evidence, not to disappear once a story has been written. Use shared tooling (`book/api/profile_tools/`) instead of reimplementing parsers.

---

## 5. Selected experiment notes (Sonoma baseline)

- **field2-atlas** – **mapped (field2-first, static + runtime)**  
  Field2-first slice that follows specific field2 IDs (`path`/`global-name`/`local` plus one static-only neighbor) across tag layouts, anchors, canonical system profiles, and runtime signatures. Static records live in `book/experiments/field2-atlas/out/static/field2_records.jsonl`, runtime results in `out/runtime/field2_runtime_results.json`, and the merged atlas/summary in `out/atlas/`. Guardrailed by `book/tests/test_field2_atlas.py` to keep baseline seeds runtime-backed and prevent atlas dropouts.
- **hardened-runtime** – **mapped (clean-channel, non-VFS runtime lane)**  
  Clean, provenance-stamped decision-stage runtime lane for non-VFS operations (mach/XPC, sysctl, IOKit, process-info, system-socket, notifications). Outputs are staged under `book/experiments/hardened-runtime/out/`; the experiment refuses to promote decision-stage evidence unless run via the launchd clean channel. VFS canonicalization is out-of-scope here except as a recorded observation field.
