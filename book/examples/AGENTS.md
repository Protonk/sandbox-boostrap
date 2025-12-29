# AGENTS

This directory contains **16 standalone examples**. They fall into two broad groups:
> Some examples are ported from 2011-era code; validate them on a specific world_id before generalizing any behavior.

- **Sandbox behavior probes** – run code under (or next to) the sandbox to see how specific operations behave.
- **Profile + regex tooling** – compile, extract, disassemble, and visualize sandbox profiles and their regex tables.

Use this map to route yourself to the right example. Each entry gives:

- What the example is for.
- How to run it.
- How it fits into the overall Seatbelt / analysis tooling story.

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

## Two main “families” of examples

You will see two broad kinds of examples here.

### 1. Sandbox behavior probes

These are the descendants of the original sandbox examples. They focus on how Seatbelt evaluates specific operations, filters, and metadata:

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

### `entitlements-evolution/`

- **Role:** Show how signing identifiers and entitlements appear at runtime and how they feed SBPL predicates like `(entitlement-is-present ...)` and `(signing-identifier ...)`.
- **Run:**
  ```sh
  # Note: example dir is docs-only; runnable probe lives under book/api/.
  python -m book.api.lifecycle_probes entitlements \
    --out book/graph/concepts/validation/out/lifecycle/entitlements.json
```

* **Concept:** Entitlements as sandbox inputs. Same binary, different signatures/entitlements → different sandbox outcomes.

---

### `platform-policy-checks/`

* **Role:** Probe sysctl, SIP-protected filesystem paths, and Mach services to highlight **platform policy running before per-process/App Sandbox SBPL**.
* **Run:**

  ```sh
  clang platform_policy.c -o platform_policy
  ./platform_policy
  ```
* **Concept:** Platform vs app sandbox layering. Use when you need examples where global rules (SIP/CSR/platform policy) can deny even if a per-process profile would allow.

---

### `extensions-dynamic/`

* **Role:** Demonstrate the `libsandbox` extension APIs (`sandbox_extension_issue_file`, `sandbox_extension_consume`, `sandbox_extension_release`) and how they map to `(extension ...)` filters.
* **Run:**

  ```sh
  # Note: example dir is docs-only; runnable probe lives under book/api/.
  python -m book.api.lifecycle_probes extensions \
    --out book/graph/concepts/validation/out/lifecycle/extensions_dynamic.md
  ```
* **Concept:** Sandbox extensions as **dynamic capabilities** stacked on top of platform and per-process policy. Expected to fail issuance on unentitled CLIs; focus is on the API pattern.

---

### `containers-and-redirects/`

* **Role:** Inspect `~/Library/Containers` and `~/Library/Group Containers`, resolve symlinks, and show the **real paths Seatbelt evaluates** for path-based filters.
* **Run:**

  ```sh
  swiftc containers_demo.swift -o containers_demo
  ./containers_demo
  ```
* **Concept:** Containers, redirects, and path filters (`subpath`, `literal`, `regex`). Use when you need examples about container layout and symlink resolution.

---

### `mach-services/`

* **Role:** Register a Mach bootstrap service and perform `mach-lookup` against it and selected system services.
* **Run:**

  ```sh
  clang mach_server.c -o mach_server
  clang mach_client.c -o mach_client

  # Terminal 1
  ./mach_server

  # Terminal 2
  ./mach_client
  ```
* **Concept:** `mach-lookup` as a sandbox operation with `(global-name "...")` filters. Shows how service names become sandbox inputs.

---

### `network-filters/`

* **Role:** Exercise TCP, UDP, and AF_UNIX sockets to map syscalls to `network-outbound` filters and associated attributes.
* **Run:**

  ```sh
  clang network_demo.c -o network_demo
  ./network_demo
  ```
* **Concept:** Network filter vocabulary (`socket-domain`, `socket-type`, remote/local addresses). Use when you need a client-only probe whose policy you can change separately.

---

### `metafilter-tests/`

* **Role:** Use `sandbox-exec` with tiny SBPL profiles to demonstrate `require-any`, `require-all`, and `require-not` behavior on `file-read*`.
* **Run:**

  ```sh
  bash metafilter_demo.sh
  ```
* **Concept:** Metafilter behavior and how OR/AND/NOT show up in compiled graphs (no explicit metafilter opcodes). Good when reasoning about “why was this path denied?” versus boolean structure.

---

### `sbpl-params/`

* **Role:** Show how `(param "...")` in SBPL can gate behavior, and how `sandbox-exec -D` may (or may not) toggle writes depending on system support.
* **Run:**

  ```sh
  bash params_demo.sh
  ```
* **Concept:** SBPL parameters as **compile/evaluation-time switches**, distinct from entitlements (signature metadata) and extensions (runtime tokens).

---

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
  - Examples that compile a sample SBPL and then immediately pass the resulting blob through the shared `book/api/profile_tools/ingestion/` layer to parse headers and slice sections (op table, node array, regex/literal tables).
Use these when you need to **compile, extract, disassemble, or visualize profiles and AppleMatch regex blobs**, not run live sandboxed workloads.


### `apple-scheme/`

* **Role:** C/clang demo calling `libsandbox`’s `sandbox_compile_*` interfaces to turn SBPL into a binary blob, illustrating the TinyScheme → compiled profile path.
* **Run:**

  ```sh
  ./run-demo.sh
  ```
* **Concept:** Minimal “call the compiler” example for SBPL → TinyScheme → bytecode. Use as a reference for private `libsandbox` compile APIs.

---

### `extract_sbs/`

* **Role:** Docs-only pointer for compiling selected installed SBPL profiles (from `/System/Library/Sandbox/Profiles`) into `.sb.bin` blobs using `book/api/profile_tools`.
* **Run:**

  ```sh
  python -m book.api.profile_tools compile \
    /System/Library/Sandbox/Profiles/airlock.sb \
    /System/Library/Sandbox/Profiles/bsd.sb \
    --out-dir book/graph/concepts/validation/fixtures/blobs \
    --no-preview
  ```
* **Concept:** Harvesting system profiles for decoding. Canonical blobs for this host are tracked at `book/graph/concepts/validation/fixtures/blobs/{airlock,bsd}.sb.bin`.

---

### `libsandcall/`

* **Role:** C demo that compiles inline SBPL, prints bytecode metadata, and probes `sandbox_apply` to show how applying a profile to the current process is typically blocked without entitlements.
* **Run:**

  ```sh
  ./run-demo.sh
  ```
* **Concept:** Direct `libsandbox` usage (`sandbox_compile_string`, `sandbox_apply`). Use when you need a minimal caller that both compiles and (tries to) apply a profile.

---

### `re2dot/`

* **Role:** Convert compiled AppleMatch regex blobs (`.re`) into Graphviz `.dot` graphs.
* **Run:**

  ```sh
  python3 re2dot.py input.re output.dot
  ```
* **Concept:** Visualizing regex NFAs from compiled profiles. Used downstream of `resnarf` or any other `.re` extractor.

---

### `resnarf/`

* **Role:** Extract AppleMatch regex blobs from **early decision-tree** sandbox profiles (`*.sb.bin`).
* **Run:**

  ```sh
  python3 resnarf.py path/to/profile.sb.bin output_dir
  ```
* **Concept:** Pulling `.re` sections out of legacy blobs so you can feed them to `re2dot` or `redis.py`/similar tools.

---

### `sb/`

* **Role:** Docs-only pointer for the sample SBPL (`sample.sb`) used as a small modern-graph witness on this host.
* **Run:**

  ```sh
  python -m book.api.profile_tools compile book/examples/sb/sample.sb \
    --out book/graph/concepts/validation/fixtures/blobs/sample.sb.bin \
    --no-preview
  ```
* **Concept:** Small end-to-end **SBPL → binary → header/sections** sample for the modern graph-based format. Canonical compiled blob: `book/graph/concepts/validation/fixtures/blobs/sample.sb.bin`.

---

### `sbdis/`

* **Role:** Disassembler for **early-format (legacy decision-tree)** sandbox profiles; reconstructs per-operation filter trees and decodes embedded regexes.
* **Run:**

  ```sh
  ./run-demo.sh path/to/legacy.sb.bin
  ```
* **Concept:** Decoding Blazakis-era decision trees. Uses the shared ingestion layer for header/section slicing, then local logic to rebuild operation/filter structures.

---

### `sbsnarf/`

* **Role:** One-shot compiler that takes an arbitrary SBPL file and emits the compiled sandbox blob using `libsandbox`.
* **Run:**

  ```sh
  python3 sbsnarf.py input.sb output.sb.bin
  ```
* **Concept:** Userland SBPL compilation without relying on Xcode/XNU sources. Use this when you just need a `.sb.bin` from SBPL and will hand it off to other tools.

---

## Routing cheatsheet

If you are an agent deciding where to work:

* **Need a minimal SBPL → blob example (modern format)?** → `sb/`
* **Need to compile arbitrary SBPL to `.sb.bin`?** → `sbsnarf/`
* **Need system `.sb.bin` blobs from `/System/Library/Sandbox/Profiles`?** → `extract_sbs/`
* **Need to disassemble legacy Blazakis-era profiles?** → `sbdis/` (+ optionally `resnarf/` + `re2dot/`)
* **Need to visualize regex NFAs?** → `resnarf/` → `re2dot/`
* **Need live probes for containers/paths/entitlements/extensions/Mach/network/sysctl/metafilters/params?** → pick from the corresponding sandbox behavior probe above.

Treat these examples as **reference labs**:

* Prefer to extend them with new probes and tests rather than rewriting core behavior.
* Canonical SBPL compilation lives under `book/api/profile_tools` (compile subcommand). Legacy regex helpers have moved here under `book/examples/regex_tools`.
* When in doubt about formats or semantics, cross-check with `book/substrate/Orientation.md`, `book/substrate/Appendix.md`, and `book/substrate/Concepts.md`.
