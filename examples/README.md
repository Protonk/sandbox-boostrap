```md
# Examples

This directory collects small, runnable examples for exploring Apple’s Seatbelt sandbox and the surrounding tooling.

Historically, this folder only contained the original **XNUSandbox** examples: tiny probes written to demonstrate specific SBPL constructs, operations, and policy behaviors. It has since been extended to include:

- The original XNUSandbox-style **sandbox probes**.
- **Support tooling examples** for compiling, disassembling, and visualizing sandbox profiles.
- **Cross-cutting demonstrations** that show how the shared ingestion layer and other utilities fit together.

The goal is to give you a set of concrete, hands-on “labs” rather than a comprehensive API reference.

---

## Layout and conventions

Each example lives in its own subdirectory, typically with:

- One or more **code files** (`*.c`, `*.swift`, `*.sh`, `*.py`, etc.).
- A short **explainer** (`lessons.md`) describing:
  - What the example is meant to show.
  - Which sandbox operations / filters it exercises.
  - How to run it and interpret the results.
- Optionally a **driver script** (`run-demo.sh`) that builds and runs the demo.

Examples are designed to be **small and focused**: usually one capability or concept per directory.

---

## Two main “families” of examples

You will see two broad kinds of examples here.

### 1. Sandbox behavior probes

These are the descendants of the original XNUSandbox examples. They focus on how Seatbelt evaluates specific operations, filters, and metadata:

- **SBPL and policy structure**
  - Minimal SBPL profiles showing `deny default`, `allow process*`, path filters (`literal`, `subpath`, `regex`), metafilters (`require-any/all/not`), and `(param "...")` usage.
- **Filesystem and containers**
  - Probes that walk `~/Library/Containers` and `~/Library/Group Containers`, resolve symlinks, and show what paths the sandbox actually sees.
- **Entitlements and platform metadata**
  - Programs that inspect their signing identifier and entitlements and explain how SBPL filters such as `(entitlement-is-present ...)` and `(signing-identifier ...)` are applied.
- **Extensions and dynamic capabilities**
  - Demos using `libsandbox` extension APIs (issue / consume / release) to illustrate how `(extension ...)` filters act as temporary capability grants.
- **Mach, network, sysctl, platform policy**
  - Probes for `mach-lookup`, various `network` socket types, `sysctl`, and SIP-protected paths, emphasizing the distinction between global platform policy and per-process SBPL.

These examples assume a macOS system with:

- `libsandbox.dylib` available.
- `sandbox-exec` present for the SBPL harnesses (where used).
- Typical macOS 13/14 behavior; exact errno results may vary by OS version and configuration.

### 2. Profile tooling and legacy formats

Other examples focus on the **artifacts** around Seatbelt rather than the live sandbox behavior:

- **SBPL → binary compilers**
  - Tiny Python helpers that call `sandbox_compile_file` via `libsandbox` and emit `.sb.bin` blobs for further analysis.
- **Legacy decision-tree disassembly**
  - Tools that target the early “decision-tree” profile format (Blazakis-era), using documented headers to reconstruct per-operation filter trees and decode embedded AppleMatch regex tables.
- **Regex extraction and visualization**
  - Extractors that snarf compiled regex blobs (`.re`) from legacy profiles.
  - Converters that turn AppleMatch NFAs into Graphviz `.dot` graphs or approximate textual regexes.
- **Modern graph-based ingestion**
  - Examples that compile a sample SBPL and then immediately pass the resulting blob through the shared `concepts/cross/profile-ingestion` layer to parse headers and slice sections (op table, node array, regex/literal tables).

These examples are useful when you are:

- Inspecting profiles from different macOS generations.
- Writing your own disassemblers, visualizers, or diff tools.
- Validating the shared ingestion layer against known-good samples.

---

## How to use these examples

A good workflow for each example directory is:

1. **Read `lessons.md` first**
   - Understand what the example is supposed to show.
   - Note any caveats (platform policy vs SBPL, entitlements, SIP, version dependencies).

2. **Skim the code**
   - Confirm which syscalls, APIs, or SBPL constructs are actually exercised.
   - Look for assumptions (paths under `/tmp`, using `/System`, specific Mach service names, etc.).

3. **Run the demo (if safe on your system)**
   - Use `run-demo.sh` where provided, or follow the commands in `lessons.md`.
   - Compare the observed behavior (errno, log messages, output) with the explanation.

4. **Relate back to the guidance docs**
   - Use:
     - `guidance/Orientation.md` for the overall pipeline and policy stacking.
     - `guidance/Appendix.md` for operation/filter vocabulary, binary formats, and regex/literal tables.
     - `guidance/Concepts.md` for cross-cutting concepts and mental models.
   - The examples are intentionally small so you can map “what the process did” to “what Seatbelt likely evaluated.”

Examples here are **illustrative**, not normative:

- They are designed to make specific ideas concrete.
- They do not attempt to cover every operation, filter, or platform quirk.
- Behavior that depends on SIP, entitlements, or OS version may vary; treat the examples as starting points for your own probes.

---

## Relationship to agent guidance

This README is aimed at **human readers** who want to learn by running code.

Separate files such as `Examples/AGENTS.md` describe how automated agents should interact with these examples and the rest of the repo. If you are working with AI-assisted tooling, read those in addition to this README; but you do not need them to run and understand the examples themselves.
```
