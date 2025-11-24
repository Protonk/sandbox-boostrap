## 1. Process summary

We started by creating two root-level orientation documents:

* `Orientation.md` – a high-level Seatbelt model aimed at code readers: operations, filters, decision graphs, SBPL → binary → kernel evaluation, and platform vs per-process policy.
* `Appendix.md` – a compact, citation-friendly reference: SBPL cheatsheet, binary profile formats and policy graphs, operations and filters, and policy stacking.

These were treated as the authoritative conceptual layer for the old XNUSandbox code and any new work.

On a separate modernization branch, a Codex “archeologist” agent was then tasked with:

* Treating each root-level folder as a **chapter anchor**: one focused idea about the sandbox, realized as a runnable example.
* Updating or adding code so that each example **builds and runs on macOS 14.x on Apple Silicon**.
* Adding short per-folder summaries and HISTORY entries to capture what changed and how it relates to the Orientation/Appendix.

Finally, the agent produced:

* `ExportExamples.md` – a concise index of the modern examples and what they demonstrate.
* `ModernizationReport.md` – a per-folder modernization report plus a short, focused ERRATA section (“orientation vs reality” on macOS 14.x).

These artifacts are now stable and are meant to be inputs to future work, not moving targets.

---

## 2. Modernized examples (by folder)

This is a synthetic overview of the examples as they now stand.

### `apple-scheme/`

* **Idea / chapter**: SBPL → TinyScheme → `libsandbox` compile path, demonstrating Stage 1→2 (source → compiled policy blob).
* **Modern example**: A small driver that:

  * Takes SBPL text,
  * Invokes `sandbox_compile_*` on modern macOS,
  * Produces a `{type, bytecode, bytecode_length}`-style artifact.
* **Outcome**: Shows that the “intermediary Scheme + compiled blob” story still holds on macOS 14.x, even though `sandbox-exec` is effectively gone.

### `extract_sbs/`

* **Idea / chapter**: Compiling system SBPL profiles and inspecting compiled blobs.
* **Modern example**: A script/tooling that:

  * Locates current `.sb` profiles,
  * Compiles them (with `--param` support for the many parametric profiles),
  * Emits artifacts with visible header, operation-pointer, node, and regex sections.
* **Outcome**: Modern path to obtain real compiled profiles that match the binary layout described in the Appendix, without scraping kernelcaches.

### `libsandcall/`

* **Idea / chapter**: Directly calling `libsandbox` APIs to compile and (attempt to) apply profiles.
* **Modern example**: C or Python (`ctypes`) harnesses that:

  * Call `sandbox_compile_*` and report success/failure and returned blobs,
  * Probe `sandbox_apply` behavior and error codes on stock macOS 14.x.
* **Outcome**: Demonstrates how far you can go with public/private `libsandbox` APIs today, and where entitlements and system hardening block “apply” paths.

### `re2dot/`

* **Idea / chapter**: Turning compiled regex NFAs into graph visualizations.
* **Modern example**: A Python tool that:

  * Parses regex tables from a compiled profile,
  * Reconstructs NFAs into a graph representation,
  * Emits Graphviz/DOT for inspection.
* **Outcome**: Gives a concrete, visual handle on the AppleMatch-style regex structures that back `(regex #"...")` filters.

### `resnarf/`

* **Idea / chapter**: Regex extraction and normalization across profiles.
* **Modern example**: A Python script that:

  * Walks compiled profiles,
  * Extracts all regexes/literals used in filters,
  * Normalizes them for comparison or documentation.
* **Outcome**: Shows the distribution of regex filters in real modern profiles and provides raw material for testing and documentation.

### `sb/` (or equivalent simple SB driver)

* **Idea / chapter**: Minimal end-to-end SBPL → compiled profile → structural dump.
* **Modern example**: A tiny tool that:

  * Takes SBPL,
  * Compiles it,
  * Dumps a decoded header/section structure or simple op → decision mapping.
* **Outcome**: A lightweight “hello world” pipeline for the modern sandbox.

### `sbdis/`

* **Idea / chapter**: Disassembling the compiled policy graph.
* **Modern example**: A tool that:

  * Reads a compiled blob,
  * Walks operation node tables and node arrays,
  * Prints a disassembly that exposes node types, filter keys/values, and edges.
* **Outcome**: Concrete evidence of how the graph-based format looks today and a bridge from bytes to the conceptual `PolicyGraph`.

### `sbsnarf/`

* **Idea / chapter**: Minimal SBPL → bytecode compiler.
* **Modern example**: A small CLI that:

  * Accepts SBPL,
  * Invokes `sandbox_compile_*`,
  * Writes out a binary file suitable for feeding into other tools (`sbdis`, `re2dot`, etc.).
* **Outcome**: A simple, composable building block for other examples and probes.

(Names and exact contents match the modernization report; this list is a conceptual roll-up.)

---

## 3. What was learned (orientation vs modern reality)

The modernization uncovered several concrete deltas and confirmations between the 2010–2011 view and macOS 14.x behavior.

### 3.1 Confirmed architecture

* **SBPL → TinyScheme → compiled blob** still exists:

  * `sandbox_compile_*` returns `{type, bytecode, bytecode_length}`-style results today.
  * The compiled blobs still look like “header + operation pointers + node arrays + literal/regex tables.”
* **Decision-graph model** is intact:

  * Modern blobs still encode per-operation graphs of filter nodes and terminal decisions.
  * The patterns corresponding to `require-all/any/not` can still be recovered from graph structure.
* **Regex NFAs** are still part of the story:

  * Regex tables are present and parseable enough to reconstruct NFAs and approximate regex strings.

These validate the core Orientation/Appendix model as broadly correct for current macOS.

### 3.2 API and tooling shifts

* **`sandbox-exec` is effectively dead as a teaching tool**:

  * It is either missing or crippled on modern macOS; examples relying on it for enforcement demos had to be redesigned as “compile + analyze” only.
* **`sandbox_apply` is gated by entitlements and system policy**:

  * On stock macOS 14.x, attempts to apply arbitrary profiles from unentitled processes fail.
  * This constrains examples to compilation and static analysis; runtime enforcement demos must be designed around entitlements or other mechanisms.
* **`libsandbox` compile functions are still present but more private**:

  * Headers and symbols are not as cleanly exposed as in 2011; modern code relies on careful linking and loading rather than public APIs.

Net effect: you can still compile and inspect policies programmatically, but “run this custom profile in a sandboxed process” is not available to unentitled userland in the way 2011 code assumed.

### 3.3 Format and profile details

* **Headers and section layouts match the graph-based model, but with version-specific tweaks**:

  * Modern profiles share the same structural idea (op-pointer tables, node arrays, regex tables), but exact field sets, counts, and IDs differ from the 2011 paper examples.
* **Many system profiles are parametric**:

  * Real `.sb` files on macOS 14.x use `(param …)` extensively.
  * TinyScheme-based compile paths will error without parameters; tools had to learn to pass parameters or avoid such profiles.
* **Profile storage has moved**:

  * Locations and packaging of system profiles have changed (no more simple kernelcache scraping).
  * The modernization relies on `libsandbox` and current filesystem locations rather than legacy paths documented in early reversing work.
* **Operation-name discovery is rougher**:

  * The old approach that assumed certain symbol layouts or kernel structs doesn’t directly apply on 14.x.
  * Modern tools can see operations implicitly (through behavior and blobs) but a clean, up-to-date op-ID ↔ name map remains an open task.

Overall: the structural model from 2011 is still a good guide, but low-level details (IDs, locations, some fields) are clearly OS-version-specific.

### 3.4 Policy application and stacking constraints

* **Platform vs process policy is more locked down in practice**:

  * While the conceptual “platform first, then process” model remains valid, modern macOS is much stricter about who can install or alter policies.
  * Examples are necessarily confined to decoding and inspecting policies that already exist, not creating arbitrary new global/process policies.
* **Integration with TCC and extensions is visible but hard to poke**:

  * Some action modifiers and filters clearly tie into modern consent and extension mechanisms, but safe/clean ways to exercise them from unentitled code are limited.
  * Modern examples note these hooks rather than trying to simulate them.

This reinforces the Orientation’s emphasis on stacking but adds a pragmatic constraint: most users are observers, not authors, of the platform policy.

### 3.5 Methodological lessons

* **2011 code is a good starting point for mental models, not for direct reuse**:

  * It highlighted where the underlying design is stable (graphs, filters, SBPL) and where it was bound to specific OS builds (paths, tool invocations, offsets).
* **Per-folder “chapter anchors” work as intended**:

  * Treating each folder as a siloed, modern example produced a useful set of concrete probes:

    * Each teaches one slice of the sandbox,
    * Each ties directly back to Orientation/Appendix sections,
    * Each surfaces at least one “orientation vs reality” delta.
* **Modernization is a productive way to learn**:

  * For both you and the model, the act of making the examples compile and run on macOS 14.x forced explicit decisions about:

    * How `libsandbox` really behaves today,
    * What compiled blobs actually look like now,
    * Where older assumptions no longer hold.

Taken together, the modernization produced:

* A set of runnable, well-documented examples on macOS 14.x,
* A consistent conceptual frame (Orientation + Appendix),
* And a first, concrete map of how the 2010–2011 Seatbelt story carries forward—and where modern systems quietly diverge.
