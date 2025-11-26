# Concept Inventory Validation Design

This document describes how we want to validate the macOS Seatbelt/XNUSandbox concept inventory with code and artifacts. It focuses on the concepts themselves: how they are grouped, what kinds of evidence each group needs, and which cross-cutting validation modes we will rely on.

The intended home for this document is the `concepts/` directory, alongside the main concept inventory.

---

## 1. Goals for Concept Inventory Validation

The concept inventory is the canonical list of Seatbelt/XNUSandbox ideas (profile, operation, filter, policy graph, etc.), with definitions and status tags. Validation gives those definitions teeth: each important concept should be tethered to empirical or structural evidence that can withstand scrutiny.

Concretely, “success” for this phase means:

1. **Per-concept witnesses**
   - Each major concept has:
     - A clear definition (already present in the inventory).
     - One or more *witnesses* in code and/or artifacts.
   - A witness is something concrete that constrains how the concept can be implemented or argued about: a parsed profile, a small SBPL snippet, a probe run, a log, etc.

2. **Evidence types are explicit**
   - For each concept, we know which kinds of evidence are relevant:
     - Static structure (what we can see in compiled profiles or binaries).
     - Dynamic behavior (what happens when we run code under a sandbox).
     - Cross-references (how names and IDs line up across sources).
   - We prefer empirical evidence when possible (14.x behavior), but we are explicit when we rely on historical or speculative sources.

3. **Mappings are visible and repeatable**
   - We can see, in a stable place:
     - How concepts map to examples (which example folders witness which concepts).
     - How concepts map to shared abstractions (profile ingestion spine, policy graph types, vocab tables).
   - These mappings are kept in a form that can be regenerated or extended as code changes.

4. **Validation scales with small, reusable spines**
   - We do not write bespoke harnesses for each individual concept.
   - Instead, we define a small set of *validation modes* (shared spines) that each exercise a cluster of related concepts:
     - Profile ingestion and static checks.
     - Microprofile + probe evaluation.
     - Vocabulary surveys.
     - Lifecycle scenarios.
   - Most concepts are validated by one or more of these modes, with a small number of examples attached.

The outcome should be that the concept inventory is not just a glossary but a map into a set of empirical and structural tests. When a concept’s definition is challenged, we can point to concrete witnesses and, ideally, rerun or extend the associated tests.

---

## 2. Concept Clusters by Evidence Type

To keep validation manageable, we group concepts by the kind of evidence that most naturally supports them. These *concept clusters* are not philosophical categories; they are “how can we actually see this?” categories.

### 2.1 Static-Format Cluster

**Purpose**

These concepts are about how profiles look when compiled and stored: the concrete bytes and structures that the kernel and libraries consume.

**Representative concepts**

- Binary Profile Header  
- Operation Pointer Table  
- Regex/Literal Table  
- Profile Format Variant  
- Compiled Profile Source (in the “blob” sense)

**Primary evidence**

- Captured compiled profiles (system profiles, small hand-compiled profiles, profiles emitted by tooling).
- Parsers that map blobs into typed structures.
- Structural invariants:
  - Offsets and sizes line up.
  - Operation tables and their indices are consistent.
  - String/regex tables are referenced correctly.

**Validation implications**

- A single “profile ingestion” spine can serve the entire static-format cluster:
  - Input: raw profile blobs.
  - Output: typed structures plus a set of invariant checks.
- For each static-format concept, the concept inventory should point to:
  - The relevant parser or ingest module.
  - The invariants that are asserted.
  - The example profiles that are used as witnesses (e.g., specific system profiles, minimal synthetic profiles).

This keeps static validation centralized: we change the ingest pipeline in one place and update the evidence for multiple concepts at once.

---

### 2.2 Semantic Graph and Evaluation Cluster

**Purpose**

These concepts describe how the sandbox decides what to allow or deny: operations, filters, decisions, and the structure of the policy graph.

**Representative concepts**

- Operation  
- Filter  
- Metafilter  
- Decision  
- Action Modifier  
- Policy Node  
- PolicyGraph  
- Policy Stack Evaluation Order  
- Profile Layer (semantics of stacking/composition)

**Primary evidence**

- Small, focused profiles or profile fragments that encode particular semantic shapes:
  - Allow-all / deny-all.
  - “Deny except X.”
  - “Allow only if regex/path filter matches.”
  - Profiles with multiple layers and overrides.
- Probes that:
  - Run under those profiles.
  - Attempt a small, explicit set of operations (file opens, network calls, IPC, etc.).
  - Record which actions succeed or fail.

**Validation implications**

- We want a “microprofile + probe” pattern:
  - For each semantic scenario, there is a tiny profile and a tiny test program/script.
  - The probe logs the attempted operations and outcomes in a structured way (e.g., JSON).
- A single evaluation harness can run these microprofiles and collect evidence:
  - For each run, we know which operations were attempted, which filters were relevant, and what the resulting decisions were.
- For each semantic concept, the concept inventory should point to:
  - Which scenarios (profiles + probes) witness the behavior.
  - What invariants are being tested (e.g., “filters of type X must cause Y under condition Z”).

A single well-designed microprofile can often witness multiple concepts at once (operation, filter, decision, action modifier, policy node shape). The point of the cluster is to exploit that reuse.

---

### 2.3 Vocabulary and Mapping Cluster

**Purpose**

These concepts are about naming and alignment: how symbolic names and argument shapes relate to on-disk IDs and observed behavior.

**Representative concepts**

- SBPL Profile (as a named aggregate)  
- Operation Vocabulary Map  
- Filter Vocabulary Map  
- Profile Format Variant (insofar as it changes vocab coverage)

**Primary evidence**

- Enumerations of operations and filters from multiple sources:
  - Documentation (Apple Sandbox Guide, etc.).
  - Reverse-engineering sources.
  - Live system profiles (extracted operation/filter tables).
  - Runtime logs from probes (which operation IDs / names actually get used).
- Cross-checks between:
  - Our canonical vocab tables.
  - Tables extracted from compiled profiles.
  - The operation and filter names referred to by examples and probes.

**Validation implications**

- A “vocabulary survey” pipeline can consolidate and check vocab knowledge:
  - Gather all op/filter names and IDs from available sources.
  - Normalize them into canonical tables.
  - Mark each entry with status (known, deprecated, unknown, 14.x-only, etc.).
- Example folders do not need to implement vocab logic themselves:
  - They should record which operations/filters they believe they are exercising (using canonical names).
  - A shared vocab-mapper can reconcile those names with IDs and on-disk representations.
- For each vocab-related concept, the concept inventory should point to:
  - The canonical vocab tables.
  - Any discrepancies or unknowns.
  - Tests or reports that compare different sources.

This cluster ensures that when we say “operation X” or “filter Y,” we can trace that name from source snippets, to IDs in compiled profiles, to behavior observed at runtime.

---

### 2.4 Runtime Lifecycle and Extension Cluster

**Purpose**

These concepts concern when and how profiles apply over a process lifetime, and how extensions modify effective policy.

**Representative concepts**

- Sandbox Extension  
- Policy Lifecycle Stage  
- Profile Layer (in the sense of system/global/app layering)  
- Any app/container-specific concepts we decide to promote to the inventory

**Primary evidence**

- Scenario-style probes that:
  - Launch processes through different paths (launchd services, GUI app launch, sandbox-exec, etc.).
  - Observe system behavior at distinct lifecycle points (e.g., pre-init, post-init, after extensions are granted).
  - Track how access changes over time in response to extensions and profile changes.

**Validation implications**

- These concepts likely require fewer, more complex examples:
  - Each scenario can witness multiple lifecycle concepts simultaneously.
- They can reuse:
  - The same static ingestion tools (to see what profiles/extensions exist).
  - The same operation/decision probes from the semantic cluster (but applied at different lifecycle stages).
- For each lifecycle concept, the concept inventory should point to:
  - Which scenarios illustrate the lifecycle transitions.
  - What kinds of extensions or profile layering are being exercised.

This cluster is more “macro” than the others, but aligning it with shared ingestion and probe tooling keeps it from becoming a separate universe.

---

## 3. Cross-Cutting Validation Modes

Concept clusters describe *what* we are validating. Validation modes describe *how* we do it. These are the shared spines that cut across clusters and examples.

We define four primary validation modes. Most concepts will be validated by one or more of these.

### 3.1 Static Ingestion Mode

**Scope**

- Covers the static-format cluster fully.
- Supports the vocabulary/mapping cluster (by reading operation/filter tables).
- Provides structural evidence for lifecycle and semantic concepts (which operations and filters exist in a given profile).

**Mechanics**

- Input: compiled profile blobs (system profiles, synthetic profiles, per-example profiles).
- Pipeline:
  - Parse into typed structures (headers, operation tables, string/regex tables, etc.).
  - Run invariant checks (lengths, offsets, references).
  - Extract vocab tables.
- Output:
  - Structured representations stored as boundary objects.
  - Reports or summaries that can be referenced from the concept inventory.

### 3.2 Microprofile Evaluation Mode

**Scope**

- Primary mode for the semantic graph/evaluation cluster.
- Also provides empirical backing for vocab entries (which operations/filters actually trigger in practice).

**Mechanics**

- Input:
  - Small profiles or profile fragments targeting specific semantic cases.
  - Tiny probes that attempt a focused set of operations.
- Pipeline:
  - Run probes under the microprofiles.
  - Record attempted operations, filters implicated (when we can infer them), and decisions.
- Output:
  - Logs or boundary objects capturing allowed/denied outcomes.
  - Per-scenario notes on which concepts and invariants are being exercised.

### 3.3 Vocabulary Survey Mode

**Scope**

- Primary mode for the vocabulary/mapping cluster.
- Relies on static ingestion and microprofile evaluation outputs, plus documentation and reverse-engineering sources.

**Mechanics**

- Input:
  - Enumerations from docs and reverse-engineering.
  - Operation/filter tables extracted from profiles.
  - Logs from probes showing real-world usage.
- Pipeline:
  - Normalize names and IDs into canonical vocab.
  - Compare across sources; flag mismatches, unknowns, and version-specific entries.
- Output:
  - Canonical vocab tables with status flags.
  - Reports summarizing discrepancies and coverage.

### 3.4 Lifecycle Scenario Mode

**Scope**

- Primary mode for the runtime lifecycle and extension cluster.
- Integrates data from all other modes in realistic process lifecycles.

**Mechanics**

- Input:
  - Scenario scripts and configurations (how to launch, when to grant extensions, what probes to run).
- Pipeline:
  - Execute scenarios step-wise.
  - At each stage, run targeted probes and capture behavior.
  - Optionally inspect or infer active profiles/extensions via system tools and logs.
- Output:
  - Scenario-level timelines of behavior.
  - Evidence of when policies take effect and how extensions modify them.

---
