# Mach services probe – mach-lookup as a stacked gate

## Context

- Host: Sonoma baseline (see `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world.json)`), SIP enabled.
- Demo: mach-services probe binaries (`mach_server` and `mach_client`, legacy local build).
- Goal: obtain a clean, empirical witness of the `mach-lookup` operation as Seatbelt sees it by probing a small demo service (`com.example.xnusandbox.demo`) and a couple of system services.

## Narrative: mach-lookup as a stacked gate

This probe was intended to show a process performing `mach-lookup` operations that Seatbelt could mediate via its `mach-lookup` PolicyGraph. What we actually observed on this host is that the sandbox never gets a say. Instead, the bootstrap subsystem—launchd’s side of the world—terminates the experiment early with `BOOTSTRAP_NOT_PRIVILEGED`.

In terms of the project’s vocabulary, `mach-lookup` is an operation in the Seatbelt policy vocabulary with filters like `(global-name "com.apple.cfprefsd.daemon")`. When a process calls into the bootstrap API, there is a conceptual pipeline:

- The client issues a Mach/Boostrap request (e.g., `bootstrap_register`, `bootstrap_look_up`) against the process’s current bootstrap port.
- The bootstrap subsystem applies its own policy about which labels may publish or resolve which services in which bootstrap namespaces.
- Only if that step succeeds do we get the steady-state picture we want: a process performing a `mach-lookup` operation that Seatbelt can mediate via its `mach-lookup` PolicyGraph for the current Seatbelt label.

On this macOS 14.4.1 host, our probe never reaches that third step. Both the server and client see `kr=0x44c` for their bootstrap calls. Decoding that with `bootstrap_strerror` yields “Permission denied”; in bootstrap terminology this is the same `BOOTSTRAP_NOT_PRIVILEGED` mentioned in the earlier notes. From the point of view of the substrate, this is a textbook example of a higher-level, non-Seatbelt gate sitting in front of the sandbox: a decision taken by bootstrap/launchd that prevents the `mach-lookup` operation from ever being evaluated by the Seatbelt PolicyGraph.

Structurally, this matters for the empirical project because it highlights the stacking model we have been using throughout the book:

- **Operation level:** `mach-lookup` is part of the sandbox operation vocabulary, with filters like `(global-name ...)` that we can see in SBPL and in compiled profiles.
- **Profile + label level:** if a process actually performs a `mach-lookup` that reaches Seatbelt, the kernel consults the `mach-lookup` entrypoint in the relevant PolicyGraphs (platform layer, app/custom layers) attached to the process’s Seatbelt label, walks the nodes, and produces an allow/deny decision (possibly modified by extensions or entitlements).
- **Adjacent control level:** bootstrap/launchd, like TCC and SIP in other examples, can short-circuit the story before Seatbelt’s graphs are even consulted. In this case, bootstrap policy on this host treats arbitrary registration and lookup from our unsandboxed, unentitled test binaries as “not privileged,” so the experiment fails at the adjacent-control layer.

For the reader of the synthetic textbook, this probe becomes less about a concrete `mach-lookup` allow/deny example and more about a cautionary story: when we design validation tasks around a specific operation (here, `mach-lookup`), we have to account for the fact that other layers—bootstrap namespaces, platform daemon policies, entitlements—may be the first and sometimes only visible gate. The logs here are still useful evidence: they show that `mach-lookup` is not a magical direct line into Seatbelt, but part of a larger stack where the effective behavior is “bootstrap policy ∧ sandbox policy ∧ adjacent controls,” just as file access is “filesystem layout ∧ containers ∧ extensions ∧ sandbox policy ∧ SIP/TCC.”

In short, the current host gives us a clear, repeatable outcome—`BOOTSTRAP_NOT_PRIVILEGED` for both demo and well-known services—that we interpret as “bootstrap veto” rather than “sandbox decision.” That aligns with the substrate’s insistence that some surfaces (like TCC and SIP) are adjacent controls and that bootstrap/launchd policy is a similarly high-churn, non-sandbox layer we have to respect when drawing capability catalogs or building worked examples.

## Status

- Status: **partial / blocked at adjacent control**.
- For this host and demo:
  - all attempted registrations and lookups for the demo and selected system services return `BOOTSTRAP_NOT_PRIVILEGED`,
  - there is no evidence that Seatbelt’s `mach-lookup` PolicyGraphs are ever consulted for these runs.
- A successful `mach-lookup` runtime witness will require:
  - a whitelisted or otherwise permitted service name and/or
  - a launch context with bootstrap privileges (for example, a proper per-user launchd job with the right configuration).

## traces

### mach-services probe notes

- Host: macOS 14.4.1 (23E224), SIP enabled.
- Build: `mach_server`/`mach_client` compiled after falling back to `bootstrap_register` (bootstrap_register2 was undeclared on this SDK). Warning about deprecation is expected.
- Run procedure:
  - Attempted to launch `mach_server` (background) then `mach_client`.
  - Server log: `bootstrap_register("com.example.xnusandbox.demo") failed: unknown error code` (kr=0x44c).
  - Client log: `mach-lookup` for demo service and for system services (`com.apple.cfprefsd.daemon`, `com.apple.securityd`) all returned kr=0x44c.
- Interpretation:
  - kr 0x44c maps to BOOTSTRAP_NOT_PRIVILEGED. Arbitrary service registration/lookup appears blocked at bootstrap level for this process context (likely platform/bootstrap policy, not SBPL alone).
  - No evidence the client ever reached Seatbelt `mach-lookup` filters; failure occurred before a successful registration/lookup.
- Next steps to get a successful witness:
  - Use an allowed/whitelisted service name or run under a context with bootstrap privileges.
  - Launch via a proper launchd plist (per-user domain) to see if registration succeeds there.
  - Instrument with logging (if possible) to confirm whether Seatbelt hooks are reached when bootstrap succeeds.

### jsonl

```
{"service": "com.example.xnusandbox.demo", "server_register": "failed", "kr_register": "0x0000044c", "kr_meaning": "BOOTSTRAP_NOT_PRIVILEGED", "note": "bootstrap_register failed; client lookup also failed"}
{"service": "com.example.xnusandbox.demo", "client_lookup": "failed", "kr": "0x0000044c", "kr_meaning": "BOOTSTRAP_NOT_PRIVILEGED", "note": "Server not registered; platform/bootstrap may block arbitrary names for unprivileged callers"}
{"service": "com.apple.cfprefsd.daemon", "client_lookup": "failed", "kr": "0x0000044c", "kr_meaning": "BOOTSTRAP_NOT_PRIVILEGED", "note": "Lookup denied/failed without sandbox profile"}
{"service": "com.apple.securityd", "client_lookup": "failed", "kr": "0x0000044c", "kr_meaning": "BOOTSTRAP_NOT_PRIVILEGED", "note": "Lookup denied/failed without sandbox profile"}
```

## Agent notes

- Rebuilt `mach_server` and `mach_client` with `clang` (bootstrap_register fallback still in use; deprecation warning expected). Environment: macOS 14.4.1 (23E224), SIP enabled.
- Direct runs after rebuild:
  - `mach_server` prints `bootstrap_register("com.example.xnusandbox.demo") failed: unknown error code` and exits 1.
  - `mach_client` reports `kr=0x44c` for the demo service and for `com.apple.cfprefsd.daemon` / `com.apple.securityd`.
- Decoded `0x44c` via `bootstrap_strerror` (python3 + ctypes): `Permission denied` (matches `BOOTSTRAP_NOT_PRIVILEGED`). Suggests failure in the bootstrap/launchd layer before Seatbelt `mach-lookup` filters would run.
- Tried to run the server under launchd to see if a managed per-user job gains bootstrap privileges:
  - `launchctl bootstrap gui/$UID /tmp/com.example.xnusandbox.demo.plist` → `Bootstrap failed: 5: Input/output error`.
  - `launchctl submit -l com.example.xnusandbox.demo -- <mach_server>` → exit 1, no job present (`launchctl print gui/$UID` shows nothing).
- Current state: both ad-hoc and launchd-invoked attempts are blocked at bootstrap registration/lookup with `BOOTSTRAP_NOT_PRIVILEGED`. No evidence that mach-lookup reached Seatbelt policy graphs; this remains an upstream bootstrap policy issue rather than an SBPL allow/deny result.

## from chat

When asked if this is expected:

Yes. From the substrate lens, mach-lookup is mediated by two layers: Seatbelt’s mach-lookup operation/(global-name ...) filters, and the bootstrap/launchd policy in front of it. Platform/bootstrap rules are a high‑churn surface and often deny arbitrary registration and lookup by unprivileged callers. Seeing BOOTSTRAP_NOT_PRIVILEGED before Seatbelt ever evaluates the mach-lookup graph is therefore consistent with what we’d expect on a stock macOS 13–14 system with SIP enabled: the bootstrap gate refuses the request, so the sandbox never gets a say. A successful demo would require a whitelisted name and/or a launch context that is allowed to register/lookup (e.g., via a proper per‑user launchd job or an entitlement), which matches the “platform policy may still deny” caveat in the example text.
