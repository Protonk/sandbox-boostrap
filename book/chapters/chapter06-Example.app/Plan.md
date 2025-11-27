### General plan for the example app with multiple sandbox incarnations

1. **Define the behavioral surface, not the UI**

   * Choose a small set of capabilities that map cleanly to core Seatbelt concepts:

     * Filesystem: read/write in container vs user home vs SIP-protected paths.
     * Network: outbound connection to a fixed host, localhost-only behavior.
     * IPC / services: a `mach-lookup` to a known service or a simple XPC helper.
     * TCC-adjacent: camera or photo picker to make TCC vs Seatbelt interactions visible.
   * Implement them as clearly named actions (buttons or CLI subcommands) so that each action is a recognizable “operation bundle” in later analysis.

2. **Design the sandbox incarnations as first-class artifacts**
   For the *same* code, plan at least four incarnations, each with a clear pedagogical role:

   * **Incarnation A: Unsandboxed baseline**

     * Built/signature without App Sandbox.
     * Shows what macOS enforces via SIP, TCC, and code signing alone, giving a reference for “what this process could do” in the absence of Seatbelt.

   * **Incarnation B: Minimal App Sandbox profile**

     * App Sandbox on, minimal entitlements (container-only file access, no network).
     * Establishes the basic App Sandbox profile layer, container behavior, and default-deny patterns for out-of-container file access.

   * **Incarnation C: Incremental entitlement variants**

     * Add entitlements one by one (network, user-selected file access, maybe broader file access).
     * For each variant, capture the resulting compiled profile and capability catalog, and compare: how does each entitlement change the set of allowed operations/filters?

   * **Incarnation D: Custom sandbox(7) profiles around the app**

     * Run the app under explicit SBPL profiles that demonstrate non-App-Sandbox structures: unusual defaults, interesting metafilter combinations, or extreme deny/allow setups.
     * Use these to illustrate SBPL syntax, parameterization, PolicyGraph structure, and how profile layers and Policy Stack Evaluation Order behave when you mix platform/app/custom layers.

   * Optionally, an **“extension-heavy” mode** that leans on user file-pickers or other mechanisms to demonstrate sandbox extensions being added and consumed by filters at evaluation time.

3. **Connect each incarnation to substrate concepts and evidence**

   * For every incarnation, plan to produce:

     * A decoded view of the relevant compiled profile(s): headers, operation pointer tables, node counts, selected graph fragments.
     * A capability catalog instance summarizing what the process can actually do (operations, filters, entitlements, extensions).
     * A handful of traces (syscall-level or conceptual) that show concrete allow/deny decisions and how they arise from the PolicyGraph and policy stack.
   * Explicitly map these outputs to the Concept and Appendix definitions: SBPL profile → Compiled Profile Source → PolicyGraph → Seatbelt label / profile layers → observable behavior.

4. **Plan for stability vs churn (State + Environment)**

   * Keep the behavior tied to architectural invariants: App Sandbox templates, containers under `~/Library/Containers/<bundle>/…`, SBPL → compiled graph pipeline, TCC prompts as a separate layer.
   * Treat exact profiles, operation inventories, and entitlements as snapshot details; structure the examples and text so they still make sense if those details shift slightly in future macOS versions.

5. **Integrate with the textbook and repository**

   * Treat the app and its profiles as part of the didactic apparatus: source code, entitlements, SBPL, compiled blobs, and capability catalogs all live in the repo and are referred to explicitly from the chapter.
   * Ensure each chapter section can say “run this incarnation, observe behavior X, and now decode/interpret it in terms of Orientation/Concepts/Appendix.”
   * Keep the app intentionally small and auditable so readers (and agents) can inspect code paths and relate them directly to sandbox decisions.

---

### Brief proposed chapter outline

Working title: **“A Small App in a Big Sandbox: A Worked Example”**

1. **2.x.1 Why this example exists**

   * Motivate the need for a controlled, open example instead of relying only on Apple’s own apps.
   * Explain that we will follow one tiny app across multiple sandbox incarnations, using the substrate’s concepts (Profile Layer, PolicyGraph, container, entitlement, extension) as our lens.

2. **2.x.2 The app: behaviors and expectations**

   * Describe the app’s features purely in behavioral terms (file/network/IPC/TCC actions), without yet mentioning sandbox details.
   * State what “should” happen in an ideal unconstrained world versus what we expect on modern macOS.

3. **2.x.3 Incarnation A: Unsandboxed baseline**

   * Show what happens when the app runs without App Sandbox: which actions succeed, which are blocked by SIP or TCC.
   * Use this to introduce the broader environment (SIP, TCC, hardened runtime) and distinguish Seatbelt from these other layers.

4. **2.x.4 Incarnation B: Minimal App Sandbox**

   * Introduce the App Sandbox entitlements used, and the resulting container.
   * Walk through a few key actions: container file access vs home directory, initial network denial, etc.
   * Link behavior back to the app’s SBPL template and its compiled PolicyGraph at a high level (Orientation + Concepts).

5. **2.x.5 Incarnation C: Entitlement-driven growth**

   * Add entitlements one at a time and observe how capabilities change.
   * For each step, compare capability catalogs and selected policy graph fragments, tying changes directly to entitlements and SBPL parameterization.
   * Emphasize the role of Compiled Profile Source, operation/filter vocabulary maps, and Policy Stack Evaluation Order.

6. **2.x.6 Incarnation D: Custom profiles and edge cases**

   * Run the app under one or more explicit sandbox(7) SBPL profiles designed to highlight:

     * default-allow vs default-deny;
     * interesting metafilters;
     * surprising deny paths.
   * Decode these profiles more deeply: headers, node arrays, pointer tables; show how graph-level structure explains observed decisions.

7. **2.x.7 Extensions and dynamic exceptions**

   * Use user-driven actions (e.g., file picker) to demonstrate sandbox extensions.
   * Connect what the reader sees (suddenly allowed paths) to the substrate’s notion of sandbox extensions and Seatbelt label / credential state.

8. **2.x.8 From example to capability catalogs**

   * Show how the example app’s incarnations become concrete entries in a capability catalog.
   * Explain how this catalog is used for comparison and risk analysis elsewhere in the book.

9. **2.x.9 Summary and next steps**

   * Recap what the reader has seen: one app, multiple Profile Layers and compiled profiles, observable behavior explained via PolicyGraph and environment layers.
   * Point forward to later chapters (e.g., deeper binary decoding, system profiles, or broader ecosystem surveys) that build on the same conceptual machinery.
