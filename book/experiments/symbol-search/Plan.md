# Symbol Search (sandbox dispatcher and regex callers)

Goal: locate the sandbox PolicyGraph dispatcher and related helpers inside `BootKernelExtensions.kc` by chasing symbol/string references (AppleMatch imports, sandbox strings, MACF hooks) and signature scans instead of raw computed-jump heuristics.

---

## 1) Scope and setup

**Done**

- Scaffolded this experiment directory (Plan, Notes, ResearchReport). Inputs: `dumps/Sandbox-private/14.4.1-23E224/kernel/BootKernelExtensions.kc`, analyzed Ghidra project `dumps/ghidra/projects/sandbox_14.4.1-23E224`, headless scripts under `dumps/ghidra/scripts/`.

**Upcoming**

- Confirm baseline metadata in `ResearchReport.md` (OS/build, SIP, tools).

Deliverables: this plan, `Notes.md`, `ResearchReport.md`; `out/` for scratch JSON listings if needed.

## 2) Expand symbol and string pivots

**Upcoming**

- Broaden string/import search: include AppleMatch entry points (e.g., `match_exec`, `match_compile`, regex helpers) and sandbox strings without restricting to sandbox blocks; emit reference lists via headless script.
- Emit a caller histogram for each matched import/string to rank likely dispatchers.

Deliverables: refreshed headless outputs under `dumps/ghidra/out/.../kernel-string-refs` (or a new task) with expanded queries and caller counts.

## 3) AppleMatch import pivot

**Upcoming**

- Enumerate external imports in sandbox.kext that resolve to AppleMatch and collect their callers; flag callers that also index shared arrays or branch on tag-like values.
- Note any adjacency to regex/literal data structures recovered from `.sb.bin` fixtures.

Deliverables: shortlists of AppleMatch callers plus addresses/functions, with notes in `Notes.md`.

## 4) MACF hook and mac_policy_ops pivot

**Upcoming**

- Locate the sandbox `mac_policy_conf`/`mac_policy_ops` struct; trace `mpo_*` entries into shared helpers.
- Identify the common helper that accepts a label/policy pointer and operation ID, and follow it into the graph-walk candidate set.

Deliverables: function addresses and linkage notes tying MACF hooks to the dispatcher, logged in `Notes.md`.

## 5) Profile structure pivot

**Upcoming**

- Parse a `.sb.bin` fixture (e.g., TextEdit) to confirm header/section offsets; build a multi-field signature.
- Scan KC `.const`/`.cstring` for matching header layouts or embedded profiles; map any walker code that indexes those structures.

Deliverables: signature JSON in `out/` if needed, plus scan results with candidate addresses.

## 6) Synthesis and stop condition

**Upcoming**

- Cross-link AppleMatch callers, MACF hook helpers, and structure scans to nominate dispatcher/action-handler functions.
- Stop when one or more functions are consistently referenced across pivots and show node-array walking with two successors and action handling.

Deliverables: summary in `ResearchReport.md` of evidence-backed dispatcher candidates and recommended next probes.
