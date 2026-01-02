# looking-glass — SANDBOX (Sonoma 14.4.1 world)

This is a high‑signal “what’s true” sheet about macOS Seatbelt *as modeled and witnessed by SANDBOX_LORE’s single host baseline* (Sonoma 14.4.1, Apple Silicon, SIP enabled; `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`). It aims to be useful for design and audit conversations, not an exhaustive reference.

If you need generic macOS sandbox lore, treat it as **generic lore** and keep it separate from what this world actually shows.

## Quick invariants (don’t get fooled)

- **Stage matters.** There is a critical difference between: `compile` → `apply` (attach) → `bootstrap` (probe start) → `operation` checks. `EPERM` at apply time is an environment gate, not a policy decision.
- **Lane matters.** Runtime evidence comes in lanes (`scenario|baseline|oracle`) that answer different questions; do not treat `oracle` as syscall observation.
- **The sandbox mediates Operations via PolicyGraphs.** “Allow/deny” happens by evaluating a compiled graph per Operation, not by interpreting SBPL at runtime.
- **Path strings are not stable.** VFS and filesystem canonicalization (e.g., `/tmp` → `/private/tmp`) can cause path‑based rules to behave differently than naive string matching suggests.
- **Policy is layered.** Effective outcomes come from a stack (platform policies, per‑process profile, auxiliary profiles, sandbox extensions) plus adjacent systems (TCC, hardened runtime, SIP).

## Core objects (project vocabulary, minimal)

- **SBPL profile**: the Scheme‑like source language for sandbox rules (`(deny default)`, `(allow file-read* (subpath "..."))`, metafilters like `require-any`).
- **Operation**: a named class of mediated action (e.g., `file-read*`, `file-write*`, `mach-lookup`, `network-outbound`).
- **Filter**: a predicate that constrains an Operation (path, vnode type, mach service name, entitlement, etc.).
- **PolicyGraph**: the compiled graph representation of rules; per‑Operation evaluation walks graph nodes until a Decision.
- **Operation pointer table**: maps Operation ID → entry node in the PolicyGraph.
- **Profile layer / stack**: multiple compiled profiles may apply to a process; outcomes combine by precedence rules.
- **Sandbox extensions**: dynamic tokens granting scoped extra permissions on top of existing profiles.

## Host-grounded facts SANDBOX_LORE relies on

- **There is a fixed Operation and Filter vocabulary for this host.** SANDBOX_LORE treats Operation/Filter names and IDs as host‑specific facts (not assumed stable across macOS versions).
- **Compiled profiles on this host are “graph-based” and decode into the objects above.** The project works in terms of headers, op‑tables, node arrays, and pooled literal/regex data.
- **A small set of canonical system profiles are treated as structural anchors.** They exist as compiled blobs and can be decoded and summarized consistently enough to support other tooling and mappings.
- **The project can compile SBPL via `libsandbox` and decode the resulting blobs.** This supports “write a profile → compile → decode → compare structure” loops even when runtime application is constrained.

## Runtime behaviors we repeatedly lean on (case studies)

- **`file-read*` / `file-write*`**: there are repeatable runtime probes in this project that exercise allow/deny behavior for these file operations under controlled profiles.
- **`mach-lookup`**: there are repeatable runtime probes that exercise allow/deny behavior for name lookup in the Mach bootstrap namespace.
- **`network-outbound`**: there are repeatable runtime probes that exercise allow/deny behavior for outbound networking under controlled profiles.
- **Other covered ops**: the current runtime corpus also includes mapped coverage for `file-read-xattr`, `file-write-xattr`, `darwin-notification-post`, `distributed-notification-post`, `process-info-pidinfo`, `signal`, `sysctl-read`, and `iokit-open-service`.
- **VFS canonicalization as a confounder**: at least one canonical scenario shows that path‑based expectations can fail because the kernel resolves paths differently than the profile’s literals (the “/tmp vs /private/tmp” class of issue).
- **Apply-time gating exists on this host**: some profile shapes and/or platform profiles cannot be attached from a generic harness identity; attempts fail before any operation check occurs.

## Adjacent systems that commonly impersonate “sandbox behavior”

- **TCC** (privacy database + prompts) can deny access even when Seatbelt would allow it.
- **Hardened runtime** can block behaviors (debugging/injection/JIT/etc.) independently of Seatbelt policy.
- **SIP / platform protections** can block filesystem and process operations even for privileged users and even outside the sandbox.

## Known unknowns (useful to keep explicit)

- **End-to-end “entitlement → parameterized template → compiled PolicyGraph → runtime decision”** is not yet a single, fully reliable story across many entitlements and services.
- **Many Operations are structurally known but not behaviorally exercised.** The vocabulary is large; runtime case studies currently cover a narrow slice.
- **Some compiled-node fields are still only partially interpreted.** Where decoded graphs contain payloads that are not mapped to a stable semantic meaning, SANDBOX_LORE treats them as bounded unknowns rather than guessing.

This sheet should help you keep design conversations grounded: if a proposal assumes away apply gating, path canonicalization, stacking, or adjacent controls, it’s probably missing the real failure mode.
