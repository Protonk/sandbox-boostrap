# Apply-gate (`EPERM`): consolidated investigation record

On `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`, you will sometimes see `EPERM` because a sandbox profile failed to attach at apply time (“apply gate”), not because the sandbox denied a specific operation. Treat any apply-stage `EPERM` as **hypothesis** evidence: the profile never became part of the process label, so no PolicyGraph decision for the intended probe could have occurred. Always triage `EPERM` by inspecting normalized runtime fields (`failure_stage`, `failure_kind`, `apply_report`) rather than reading raw stderr.

A validated witness corpus makes this behavior mechanically reproducible on this world under the same harness identity. Across four witnesses, compilation succeeds while `sandbox_apply` fails with `EPERM`, and the minimal failing profiles share deny-style `apply-message-filter` structure; micro-variants show that `apply-message-filter` alone is not sufficient because some allow-style variants successfully apply and then fail later at bootstrap. During the failing apply window, bounded unified-log captures include the reason string “missing message filter entitlement,” while the applying process’s entitlement check reports `com.apple.private.security.message-filter` absent; treat this as strong correlation evidence, not a sufficiency proof.

Operationally, we avoid re-learning this failure mode by relying on guardrails rather than memory. SBPL-wrapper emits structured JSONL markers and defaults to preflight enforcement, so known apply-gate signatures short-circuit to `failure_stage:"preflight"` instead of producing misleading apply-stage `EPERM` records. When we need an enterable profile, consult preflight (and the repo-wide enterability manifest) and prefer profiles with no known apply-gate signature; when we need to study the gate, use the witness bundles and their passing-neighbor controls as the auditable boundary objects.

## How to read

Evidence tiers used here (SANDBOX_LORE discipline):

- **hypothesis**: apply-stage failures where the intended Profile never attached; not runtime evidence of any Operation+Filter decision.
- **mapped**: host-witnessed runtime behavior that is scenario-scoped and explicitly not generalized.
- **bedrock**: reserved for static structure claims that are explicitly surfaced as bedrock elsewhere; this report does not promote new bedrock surfaces.

Single most important operational invariant:

> apply-stage `EPERM` is **hypothesis** evidence (the Profile did not attach; no PolicyGraph decision for the intended probe can have occurred).

Definition (used throughout): **harness identity** means the applying binary **and** its signing/entitlements context, plus the surrounding execution context (notably: some in-harness contexts can be globally apply-gated, making “everything fails with EPERM” non-profile-specific).

If you read only three artifacts, read these (linear, mechanical):

1. [`book/graph/concepts/validation/out/experiments/gate-witnesses/witness_results.json`](../../book/graph/concepts/validation/out/experiments/gate-witnesses/witness_results.json)
2. [`book/graph/concepts/validation/out/experiments/gate-witnesses/forensics/airlock/log_show_primary.minimal_failing.txt`](../../book/graph/concepts/validation/out/experiments/gate-witnesses/forensics/airlock/log_show_primary.minimal_failing.txt)
3. [`book/graph/concepts/validation/out/experiments/gate-witnesses/forensics/airlock/log_show_primary.passing_neighbor.txt`](../../book/graph/concepts/validation/out/experiments/gate-witnesses/forensics/airlock/log_show_primary.passing_neighbor.txt)

## Why you care

If you treat apply-stage `EPERM` as a denial, you launder **hypothesis** evidence into “the sandbox denied X” stories and poison any aggregation or coverage summary. This also blocks a common workflow on this world: using canonical `sys:*` profiles (notably `sys:airlock`) as runnable probes under the generic harness identity.

The durable outcome here is mechanical, not narrative: tool markers → normalized `failure_stage`/`failure_kind` → witness corpus + controls + guardrails. In under five minutes, this report should let you triage an `EPERM` by stage, pick an enterable profile via preflight, and find the exact witness artifacts that justify our current “why” hypothesis. It should also make the regression guardrails visible so future tooling doesn’t slide back into substring inference.

## Glossary

- **Profile lifecycle**: the sequence “compile → apply/attach → (optional) exec probe → probe actions,” where failures have distinct evidentiary meaning.
- **Process label**: the effective sandbox label/stack for a process after successful apply; apply-gated failures never reach this state.
- **PolicyGraph evaluation**: decision-stage evaluation of an Operation+Filter under an attached policy (not reached when apply fails).
- **Probe**: the in-sandbox command/process used to attempt an Operation and observe outcomes.
- **Tool markers / JSONL markers**: structured JSON lines emitted by tools on stderr that the runtime contract uses to derive stage/kind fields.
- **Harness identity**: the applying binary plus its signing/entitlements context, plus surrounding execution context (some contexts are globally gated).
- **Control-ok vs global gate**: a control-ok context is one where known-good applies succeed; a global gate context is one where *everything* fails apply (making per-profile conclusions invalid).

## Problem statement (what “apply gate” means here)

“Apply gate” is SANDBOX_LORE’s name for **apply-stage** failures where a Profile never becomes part of the process label because the attempt to install it fails at `sandbox_init` (SBPL text apply) or `sandbox_apply` (compiled `.sb.bin` apply), with `errno == EPERM` (“Operation not permitted”).

In substrate terms, this is a **Profile lifecycle** failure prior to PolicyGraph evaluation. It is treated as **hypothesis** evidence: when apply fails, no PolicyGraph decision for the intended probe can have occurred.

The repository-wide phase discipline lives in [`troubles/EPERMx2.md`](../../troubles/EPERMx2.md), but the key idea is simple: apply-stage `EPERM` is **not** a “sandbox denied operation X” statement, and only decision-stage failures (after successful apply) are eligible to support semantic claims (and only within the repo’s status-tagged runtime coverage).

## Triage decision tree (if you saw `EPERM`)

1. Inspect the **normalized runtime IR** first (do not start with raw stderr strings):
   - `failure_stage`
   - `failure_kind`
   - `apply_report` (`api`, `rc`, `errno`, `err_class`, `errbuf`)
   - marker presence in raw stderr (optional forensic): `tool:"sbpl-apply"` / `tool:"sbpl-preflight"` / `tool:"entitlement-check"`
2. If `failure_stage == "apply"`:
   - Treat as **hypothesis** evidence (Profile did not attach).
   - Use preflight (and the preflight-index manifest) to choose a non-gated profile unless you are explicitly studying apply gates.
3. If `failure_stage == "bootstrap"`:
   - Treat as “probe did not start” under an attached policy (often `process-exec*`-related) and keep it distinct from “the sandbox denied my file/mach op.”
4. If `failure_stage` is empty/`null` but the tool did not run:
   - Treat as harness/tooling error (`invalid`), not sandbox evidence.
5. If `failure_stage` indicates decision-stage/probe outcomes:
   - Treat as **mapped** runtime evidence and keep it scenario-scoped; do not generalize beyond the specific probe and inputs.

## Project impact

**False semantic inference** is the main failure mode: apply-gate `EPERM` can masquerade as “the sandbox denied X” and contaminate any aggregation that treats “EPERM anywhere” as a decision-stage deny (guardrail: normalized stage/kind + explicit `apply_report`). **Blocked experimentation** is the practical cost: some canonical system profiles are not enterable as runnable probes on this world under the generic harness identity (guardrail: witness corpus + preflight + preflight-index manifest). **Regression risk** is the long tail: without a stable contract, future tooling changes can reintroduce substring inference and silently collapse phase meaning (guardrail: wrapper markers + contract upgrader + tests enforcing marker/phase invariants).

## The core confusion we had to eliminate (EPERM is not one signal)

Early on, multiple harnesses and tools surfaced `EPERM` in different places, and we repeatedly collapsed those distinct signals into a single story (“the sandbox denied X”). SANDBOX_LORE now keeps phase meaning mechanically distinct in normalized runtime IR derived from tool markers (no stderr substring inference). The core code surfaces are SBPL-wrapper ([`book/tools/sbpl/wrapper/wrapper.c`](../../book/tools/sbpl/wrapper/wrapper.c)), the runtime contract ([`book/api/runtime/SPEC.md`](../../book/api/runtime/SPEC.md)), and the harness runner/normalizer ([`book/api/runtime/execution/harness/runner.py`](../../book/api/runtime/execution/harness/runner.py), [`book/api/runtime/contracts/normalize.py`](../../book/api/runtime/contracts/normalize.py)).

- **apply**: `sandbox_init` / `sandbox_apply` fails → Profile never attaches (hypothesis evidence).
- **bootstrap**: apply succeeded, but the probe cannot start (e.g., `execvp` fails, sometimes plausibly due to `process-exec*` denial).
- **probe**: the probe ran and returned nonzero (may or may not reflect a sandbox decision).
- **decision-stage** denials: syscall-level `EPERM` after apply success (mapped evidence; scenario-scoped).

## Investigation chronology

### 1) Initial symptom: system profile blobs failing apply

The first recurring apply-stage failure was observed when trying to apply canonical system blobs via `sandbox_apply`, especially `sys:airlock`. This was recorded early in [`troubles/EPERM_chasing.md`](../../troubles/EPERM_chasing.md) and expanded in [`troubles/profile_blobs.md`](../../troubles/profile_blobs.md).

Custom/synthetic blobs applied cleanly while some system profiles (notably `airlock`) failed to apply with `EPERM`, which quickly became a practical blocker for runtime harness work (notably the `runtime-checks` corpus trying to treat canonical `sys:*` blobs as runnable probes on this world). See [`book/experiments/runtime-checks/Report.md`](../../book/experiments/runtime-checks/Report.md) for the “blocked by apply-stage EPERM” framing in that experiment’s own vocabulary.

At this point, our framing was still narrow (“platform/system profiles are gated”) and confounded by three factors we later had to eliminate: uncertainty about whether we were even calling the right apply API, structural observations about blob headers (e.g., `maybe_flags=0x4000` on `airlock`), and a plausible but unproven provenance/credential gate story.

Those notes are valuable history, but they did not yet yield a stable, testable boundary object.

### 2) Make failure classification mechanical (stop reading tea leaves in stderr)

The turning point was treating the apply gate as a classification problem rather than a one-off failure: we standardized the apply surface behind a single choke point (`SBPL-wrapper`), emitted structured markers per phase (apply/applied/exec; plus entitlement and preflight markers), and normalized into stable runtime fields (`failure_stage`, `failure_kind`, `apply_report`) so downstream code never has to infer “did apply happen?” from stderr strings. This is implemented across the wrapper/marker emitters ([`book/api/runtime/native/tool_markers.h`](../../book/api/runtime/native/tool_markers.h), [`book/tools/sbpl/wrapper/wrapper.c`](../../book/tools/sbpl/wrapper/wrapper.c)), normalization ([`book/api/runtime/contracts/schema.py`](../../book/api/runtime/contracts/schema.py), [`book/api/runtime/contracts/normalize.py`](../../book/api/runtime/contracts/normalize.py)), and harness runner usage ([`book/api/runtime/execution/harness/runner.py`](../../book/api/runtime/execution/harness/runner.py)).

The outcome is that “apply gate” became an explicit, regression-testable predicate: `failure_stage=="apply"` with `apply_report.errno==EPERM`.

<details>
<summary>Marker contract example (raw vs normalized)</summary>

This example is taken from a minimizer run (`preflight minimize-gate`) that recorded both the raw stderr marker stream and the normalized outcome.

Raw stderr excerpt (from `book/experiments/gate-witnesses/out/witnesses/airlock/run.json`, `minimal_failing_outcome.raw_stderr`):

```text
sandbox initialization failed: Operation not permitted
{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","mode":"sbpl","api":"sandbox_init","rc":-1,"errno":1,"errbuf":"Operation not permitted","err_class":"errno_eperm","err_class_source":"errno_only","profile":"/var/folders/ff/qyyjgwss7m110t6fnj2qtpjr0000gn/T/tmphe8cams8.sb","pid":63214}
sandbox_init failed: Operation not permitted
```

Normalized outcome excerpt (same file, `minimal_failing_outcome`), showing that markers are not needed downstream to recover phase meaning:

```json
{
  "failure_stage": "apply",
  "failure_kind": "sandbox_init_failed",
  "apply_report": {
    "api": "sandbox_init",
    "rc": -1,
    "errno": 1,
    "errbuf": "Operation not permitted",
    "err_class": "errno_eperm",
    "err_class_source": "errno_only"
  },
  "stderr_canonical": "sandbox initialization failed: Operation not permitted\nsandbox_init failed: Operation not permitted\n"
}
```

</details>

### 3) Produce a durable witness corpus (delta-debug the gate)

To avoid hand-wavy “airlock is special” narratives, we built a minimizer that turns “apply-stage EPERM” into a shrinkable target: delta-debug an apply-gated SBPL profile into:

- `minimal_failing.sb` (still apply-gated), and
- `passing_neighbor.sb` (a one-deletion neighbor that is not apply-gated).

This is now surfaced as `preflight minimize-gate`:

- Tool: [`book/tools/preflight/preflight.py`](../../book/tools/preflight/preflight.py) (`minimize-gate`)
- Implementation: [`book/tools/preflight/gate_minimizer.py`](../../book/tools/preflight/gate_minimizer.py)
- Experiment + checked-in witness pairs: [`book/experiments/gate-witnesses/`](../../book/experiments/gate-witnesses/)

The current witness corpus is described in [`book/experiments/gate-witnesses/Report.md`](../../book/experiments/gate-witnesses/Report.md) and is enforced by validation outputs in:

- [`book/graph/concepts/validation/out/experiments/gate-witnesses/witness_results.json`](../../book/graph/concepts/validation/out/experiments/gate-witnesses/witness_results.json)
- Forensics directory with compiled blobs + unified-log capture: [`book/graph/concepts/validation/out/experiments/gate-witnesses/forensics/`](../../book/graph/concepts/validation/out/experiments/gate-witnesses/forensics)

Notation used below:

- `[airlock]` means: the `airlock` witness entry in `R`, plus its forensics bundle `F/airlock/`.
- Likewise: `[blastdoor]`, `[com.apple.CoreGraphics.CGPDFService]`, `[mach_bootstrap_deny_message_send]`.

Path stems used below (to keep this report readable without losing auditability):

- `R = book/graph/concepts/validation/out/experiments/gate-witnesses/witness_results.json`
- `W = book/experiments/gate-witnesses/out/witnesses/<id>/`
- `F = book/graph/concepts/validation/out/experiments/gate-witnesses/forensics/<id>/`

#### Witness Summary Table (validated)

The table below is the validated witness set on this world (`airlock`, `blastdoor`, `com.apple.CoreGraphics.CGPDFService`, `mach_bootstrap_deny_message_send`).

Field source conventions (so every cell is checkable by linear reading):

- `compile rc` = `R` → `witnesses[].forensics.compile.minimal_failing.marker.rc`
- `apply errno` = `R` → `witnesses[].forensics.blob_apply.minimal_failing.apply_report.errno` (and `failure_stage == "apply"`)
- `unified log hit?` = `F/<id>/log_show_primary.minimal_failing.txt` contains “missing message filter entitlement” **and** `F/<id>/log_show_primary.passing_neighbor.txt` has no such line
- `entitlement-check present?` = `R` → `witnesses[].forensics.blob_apply.minimal_failing.entitlement_checks[]` contains `com.apple.private.security.message-filter`

| witness_id | origin (minimized from) | minimal_failing.sb | passing_neighbor.sb | compile rc | apply errno | unified log hit? | entitlement-check present? |
|---|---|---|---|---:|---:|---|---|
| `airlock` | `/System/Library/Sandbox/Profiles/airlock.sb` | `W/airlock/minimal_failing.sb` | `W/airlock/passing_neighbor.sb` | 0 | 1 | yes (mf) / no (pn): `F/airlock/log_show_primary.*.txt` | yes (`present:false`) |
| `blastdoor` | `/System/Library/Sandbox/Profiles/blastdoor.sb` | `W/blastdoor/minimal_failing.sb` | `W/blastdoor/passing_neighbor.sb` | 0 | 1 | yes (mf) / no (pn): `F/blastdoor/log_show_primary.*.txt` | yes (`present:false`) |
| `com.apple.CoreGraphics.CGPDFService` | `/System/Library/Sandbox/Profiles/com.apple.CoreGraphics.CGPDFService.sb` | `W/com.apple.CoreGraphics.CGPDFService/minimal_failing.sb` | `W/com.apple.CoreGraphics.CGPDFService/passing_neighbor.sb` | 0 | 1 | yes (mf) / no (pn): `F/com.apple.CoreGraphics.CGPDFService/log_show_primary.*.txt` | yes (`present:false`) |
| `mach_bootstrap_deny_message_send` | `book/experiments/gate-witnesses/out/micro_variants/base_v2_mach_bootstrap_deny_message_send.sb` | `W/mach_bootstrap_deny_message_send/minimal_failing.sb` | `W/mach_bootstrap_deny_message_send/passing_neighbor.sb` | 0 | 1 | yes (mf) / no (pn): `F/mach_bootstrap_deny_message_send/log_show_primary.*.txt` | yes (`present:false`) |

#### End-to-end witness example

Example witness: `airlock` ([airlock]).

Minimal failing SBPL (from `W/airlock/minimal_failing.sb`):

```lisp
(version 2)
(allow iokit-open-user-client (apply-message-filter (deny iokit-external-method)))
```

Compile step (excerpt from `R`, `witnesses[target=="airlock"].forensics.compile.minimal_failing.marker`):

```json
{"rc":0,"errno":0,"bytecode_length":513,"profile_type":0}
```

Apply step (excerpt from `R`, `…forensics.blob_apply.minimal_failing`):

```json
{"failure_stage":"apply","failure_kind":"sandbox_apply_failed","apply_report":{"api":"sandbox_apply","rc":-1,"errno":1,"errbuf":"Operation not permitted"}}
```

Unified log capture (excerpt from `F/airlock/log_show_primary.minimal_failing.txt`):

```text
2025-12-19 11:06:53.727924-0800  localhost kernel[0]: (Sandbox) wrapper[3331]: missing message filter entitlement
```

Passing-neighbor control window (excerpt from `F/airlock/log_show_primary.passing_neighbor.txt`):

```text
Timestamp                       (process)[PID]
```

Effective entitlement marker (excerpt from `R`, `…forensics.blob_apply.minimal_failing.entitlement_checks[0]`):

```json
{"entitlement":"com.apple.private.security.message-filter","present":false,"pid":3331,"stage":"pre_apply","rc":0}
```

Minimal failing vs passing neighbor boundary (a one-deletion diff; from `W/airlock/{minimal_failing.sb,passing_neighbor.sb}`):

```diff
--- W/airlock/minimal_failing.sb
+++ W/airlock/passing_neighbor.sb
@@ -1,2 +1 @@
 (version 2)
-(allow iokit-open-user-client (apply-message-filter (deny iokit-external-method)))
```

The key value of the witness corpus is that later work can cite specific witness IDs (and their recorded compile/apply/log/entitlement evidence) instead of narrating `EPERM` from memory.

### 4) Tighten “what triggers the gate” (IOKit and non-IOKit scope)

Clarification: “message filter” in this report means **sandbox message filtering rules** expressed via SBPL `apply-message-filter` (Mach / IOKit message filtering), not any kind of email/SMS/content filtering.

Scope note: everything in this section is **mapped** and scoped to this world + harness identity + the validated witness set and micro-variant matrix. We treat it as a trigger-shape story for “what reliably predicts apply-gating here,” not as a general statement about message filtering across macOS versions or signing contexts.

#### System-profile witnesses (IOKit)

Across the three system-profile witnesses in the validated set, the minimal failing SBPL reduces to a closely related core pattern: the same `allow` form, with only the SBPL `version` form differing (`version 1` vs `version 2`).

Concrete excerpts (from each witness’s `minimal_failing.sb`):

```lisp
airlock:
  (version 2)
  (allow iokit-open-user-client (apply-message-filter (deny iokit-external-method)))

blastdoor:
  (version 1)
  (allow iokit-open-user-client (apply-message-filter (deny iokit-external-method)))

com.apple.CoreGraphics.CGPDFService:
  (version 2)
  (allow iokit-open-user-client (apply-message-filter (deny iokit-external-method)))
```

#### Non-IOKit witness (Mach)

To scope whether this gate was IOKit-specific vs message-filtering-gated more generally, we also built and minimized a non-IOKit witness that triggers the same apply-stage EPERM boundary under the same harness identity.

Concrete excerpt (from `book/experiments/gate-witnesses/out/witnesses/mach_bootstrap_deny_message_send/minimal_failing.sb`):

```lisp
(allow mach-bootstrap (apply-message-filter (deny mach-message-send)))
```

#### Micro-variants: “deny-style” vs “allow-style” message filtering

The gate-witnesses micro-variant matrix (`book/experiments/gate-witnesses/out/compile_vs_apply.json`) records a small set of one-edit variants with explicit compile and blob-apply results.

The table below is a derived view that turns those JSON records into a readable contrast. “Filter shape” is an SBPL-shape label (“does the `apply-message-filter` payload contain a `deny` form?”), not a semantic claim.

| variant id | filter shape | apply rc | apply errno | failure_stage |
|---|---|---:|---:|---|
| `base_v2` | deny-style | -1 | 1 | apply |
| `base_v2_inner_deny_async_external_method` | deny-style | -1 | 1 | apply |
| `base_v2_inner_deny_external_trap` | deny-style | -1 | 1 | apply |
| `base_v2_mach_bootstrap_deny_message_send` | deny-style | -1 | 1 | apply |
| `base_v2_mach_bootstrap_allow_only_with_file_write` | allow-style | 0 | 0 | bootstrap |
| `base_v1` | deny-style | -1 | 1 | apply |
| `base_v1_outer_iokit_open` | deny-style | -1 | 1 | apply |
| `base_v1_inner_allow_external_method` | allow-style | 0 | 0 | bootstrap |
| `base_v1_inner_deny_async_external_method` | deny-style | -1 | 1 | apply |
| `base_v1_inner_deny_external_trap` | deny-style | -1 | 1 | apply |

This is sufficient to support the narrow statement “`apply-message-filter` presence alone is not sufficient to produce apply-stage EPERM on this world,” because at least two allow-style variants show `apply rc == 0` while still failing later at bootstrap (exec denied).

<details>
<summary>Raw micro-variant records (excerpt)</summary>

Source: `book/experiments/gate-witnesses/out/compile_vs_apply.json` (see `micro_variants[]`).

```json
[
  {
    "id": "base_v2_inner_deny_external_trap",
    "sbpl": "book/experiments/gate-witnesses/out/micro_variants/base_v2_inner_deny_external_trap.sb",
    "apply_blob": {
      "report": {
        "failure_stage": "apply",
        "failure_kind": "sandbox_apply_failed",
        "apply_report": { "api": "sandbox_apply", "rc": -1, "errno": 1 }
      }
    }
  },
  {
    "id": "base_v2_mach_bootstrap_deny_message_send",
    "sbpl": "book/experiments/gate-witnesses/out/micro_variants/base_v2_mach_bootstrap_deny_message_send.sb",
    "apply_blob": {
      "report": {
        "failure_stage": "apply",
        "failure_kind": "sandbox_apply_failed",
        "apply_report": { "api": "sandbox_apply", "rc": -1, "errno": 1 }
      }
    }
  },
  {
    "id": "base_v2_mach_bootstrap_allow_only_with_file_write",
    "sbpl": "book/experiments/gate-witnesses/out/micro_variants/base_v2_mach_bootstrap_allow_only_with_file_write.sb",
    "apply_blob": {
      "report": {
        "failure_stage": "bootstrap",
        "failure_kind": "bootstrap_deny_process_exec",
        "apply_report": { "api": "sandbox_apply", "rc": 0, "errno": 0 }
      }
    }
  },
  {
    "id": "base_v1_inner_allow_external_method",
    "sbpl": "book/experiments/gate-witnesses/out/micro_variants/base_v1_inner_allow_external_method.sb",
    "apply_blob": {
      "report": {
        "failure_stage": "bootstrap",
        "failure_kind": "bootstrap_deny_process_exec",
        "apply_report": { "api": "sandbox_apply", "rc": 0, "errno": 0 }
      }
    }
  }
]
```

</details>

These micro-variant results are **mapped** evidence: they are host-witnessed on this world and under this harness identity, but they are not treated as a universal statement about all message filtering forms or all execution contexts.

### 5) Split compile vs apply (where the enforcement occurs)

Mechanics (API disambiguation for this narrative):

- `sandbox_init` is a combined path (compile + apply for SBPL text).
- `sandbox_compile_*` compiles SBPL into a compiled profile blob (a `sandbox_profile_t`-shaped object in the `libsandbox` API surface).
- `sandbox_apply` is the attach/apply step for a compiled blob.

Because `sandbox_init` is a combined “compile + apply” path, early “`sandbox_init` failed with EPERM” observations could not tell us whether the gate lived in:

- the user-space compiler (rejecting the SBPL form at compile time), or
- apply/attach validation (rejecting the profile at `sandbox_apply` time).

The gate-witnesses suite explicitly performs:

- compile: `sandbox_compile_file` (`tool:"sbpl-compile"`), then
- apply: `sandbox_apply` on the produced blob (`tool:"sbpl-apply"` with `api:"sandbox_apply"`),

and records both.

On this world, for the confirmed witnesses:

- compilation succeeds (`rc==0`), but
- apply fails at `sandbox_apply` with apply-stage `EPERM`.

This supports the narrow statement: **on this world and under this harness identity, across the validated witness set, compilation succeeded and `sandbox_apply` failed with `EPERM`.**

It does not prove that “no compile-time rejection exists” in general; it only bounds what we observed for this witness set on this host.

### 6) Close the loop on “why EPERM” with a host-grounded enforcement trace

The strongest move from “correlated hypothesis” toward “mechanically grounded claim” was capturing a direct enforcement trace via unified logs during the apply failure.

For the minimal failing blob applies, the unified-log capture (from `/usr/bin/log show --style syslog` in the validation job) contains a single Sandbox line (rendered as `kernel[0]` in syslog style) that includes the wrapper PID and the reason string “missing message filter entitlement”. We treat this as bounded log provenance (PID- and timestamp-scoped, with a passing-neighbor control window), not as a blanket claim about where the enforcement logic “lives”.

Reproducible log capture (example: `airlock` minimal-failing window; from `R`, `…forensics.unified_log.minimal_failing.primary.cmd`):

```sh
/usr/bin/log show --style syslog --start @1766171211 --end @1766171215 --predicate '(((subsystem == "com.apple.sandbox.reporting") OR (senderImagePath CONTAINS[c] "/Sandbox")) AND ((eventMessage CONTAINS[c] "message filter") OR (eventMessage CONTAINS[c] "message-filter") OR (eventMessage CONTAINS[c] "entitlement"))) AND (eventMessage CONTAINS[c] "wrapper[3331]")'
```

Concrete excerpts (one line per witness, from each witness’s `log_show_primary.minimal_failing.txt`):

```text
airlock: 2025-12-19 11:06:53.727924-0800  localhost kernel[0]: (Sandbox) wrapper[3331]: missing message filter entitlement
blastdoor: 2025-12-19 11:06:54.672919-0800  localhost kernel[0]: (Sandbox) wrapper[3341]: missing message filter entitlement
com.apple.CoreGraphics.CGPDFService: 2025-12-19 11:06:55.200211-0800  localhost kernel[0]: (Sandbox) wrapper[3353]: missing message filter entitlement
mach_bootstrap_deny_message_send: 2025-12-19 11:06:55.686235-0800  localhost kernel[0]: (Sandbox) wrapper[3363]: missing message filter entitlement
```

Each witness also carries the corresponding passing-neighbor log window (`F/<id>/log_show_primary.passing_neighbor.txt`), and `R` records the wrapper PID + bounded timestamps + the exact `log show` predicate used for capture.

In parallel, SBPL-wrapper emits an **effective entitlement** marker prior to apply (`tool:"entitlement-check"` for `com.apple.private.security.message-filter`).

In witness validation records, the entitlement marker is emitted by the same PID that attempts blob apply, and it reports `present:false` for the entitlement key. (See Appendix witness bundles; each includes the exact marker object.)

Taken together, the best current summary claim (still **mapped**, but strongly corroborated on this world) is:

> On this host baseline and for this harness identity, the unified log capture includes the reason string “missing message filter entitlement” during the bounded failing-apply window for each confirmed witness, while the applying wrapper process’s effective-entitlement marker reports `com.apple.private.security.message-filter` absent. This is strong correlation evidence for an entitlement gate on deny-style message filtering, but it is not a proof of sufficiency without a positive-control run.

**Non-goals / boundaries (must-not-overstate)**

- Not proving sufficiency: we do not (and may not be able to) endow the harness identity with the private entitlement as a positive control.
- Not generalizing beyond this world + harness identity + witness set.
- Not claiming a blessed enforcement site: we have log + xref hints, not a fully localized validator implementation.
- Not letting log strings or callouts become semantics: the witness corpus remains about apply-stage attachment failure, not operation-level deny decisions.

We intentionally do **not** upgrade this to bedrock: we have not (and may not be able to) produce a positive-control run where the harness is granted that entitlement and the same profile applies successfully.

Static corroboration exists but remains explicitly weaker than the log trace:

- codesign “presence” scan for the entitlement key on a small set of system executables: [`book/experiments/gate-witnesses/out/entitlements_scan.json`](../../book/experiments/gate-witnesses/out/entitlements_scan.json) (mapped; presence is not causality)
- kernel string presence + xrefs for related strings (brittle/partial, but helps locate likely call sites): [`book/experiments/gate-witnesses/out/message_filter_xrefs.json`](../../book/experiments/gate-witnesses/out/message_filter_xrefs.json)

<details>
<summary>Receipt: code paths that emit the entitlement + apply markers</summary>

Effective entitlement check (query + marker emission), from `book/tools/sbpl/wrapper/wrapper.c`:

```c
static void emit_message_filter_entitlement_check_marker(const char *stage) {
    const char *entitlement = "com.apple.private.security.message-filter";
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    /* ... */
    CFTypeRef value = SecTaskCopyValueForEntitlement(task, key, &error);
    /* ... */
    if (!value) {
        sbl_emit_entitlement_check_marker(stage, entitlement, 0, 0, -1, "absent", NULL);
    } else if (CFGetTypeID(value) == CFBooleanGetTypeID()) {
        int b = CFBooleanGetValue((CFBooleanRef)value) ? 1 : 0;
        sbl_emit_entitlement_check_marker(stage, entitlement, 0, 1, b, "bool", NULL);
    }
    /* ... */
}
```

Marker emission details (PID included; apply markers around `sandbox_apply`), from `book/api/runtime/native/tool_markers.h`:

```c
static void sbl_emit_entitlement_check_marker(/* ... */) {
    /* ... */
    sbl_json_emit_kv_string(out, &first, "tool", SANDBOX_LORE_ENTITLEMENT_CHECK_TOOL);
    sbl_json_emit_kv_string(out, &first, "entitlement", entitlement);
    sbl_json_emit_kv_int(out, &first, "pid", (long)getpid());
    /* ... present/value_type/error ... */
    fputs("}\n", out);
}

static sbl_apply_report_t sbl_sandbox_apply_with_markers(/* ... */) {
    errno = 0;
    int rc = apply_fn ? apply_fn(compiled_profile) : -1;
    int saved_errno = errno;
    const char *errbuf = (saved_errno != 0) ? strerror(saved_errno) : NULL;
    sbl_emit_sbpl_apply_marker("blob", "sandbox_apply", rc, saved_errno, errbuf, profile_path);
    if (rc == 0) sbl_emit_sbpl_applied_marker("blob", "sandbox_apply", profile_path);
    return sbl_apply_report_from_parts("blob", "sandbox_apply", rc, saved_errno, errbuf, profile_path);
}
```

</details>

## Operational resolution (how we prevented re-learning this pain)

Once we had a stable witness predicate and a scoped trigger signature, we turned the result into guardrails so later agents do not need to rediscover it.

### What changed in the repo because of this

Previously, apply-stage `EPERM` surfaced through ad‑hoc stderr substring inference (“EPERM means deny”) and inconsistent apply entrypoints (`sandbox-exec`, direct `sandbox_apply`, example scripts), which made phase meaning easy to lose. This let apply-gated failures leak into semantic tallies as if they were decision-stage denies.

Now, SBPL-wrapper is the choke point for applies and emits structured markers for apply/applied/exec plus entitlement and preflight, and a normalized runtime contract (`failure_stage`, `failure_kind`, `apply_report`) makes downstream consumers stop inferring “did we attach?” from raw stderr. A validated witness corpus with bounded forensics controls makes “apply gate exists” a regression-tested boundary object, and conservative preflight + digest/manifest guardrails keep agents away from known dead ends by default.

### Preflight guardrail (static, conservative)

`book/tools/preflight` is a cheap, static classifier intended to answer the operational question “will this profile likely be apply-gated for the harness identity?” without attempting apply:

- Tool + docs: [`book/tools/preflight/`](../../book/tools/preflight/)
- Scanner: `python3 book/tools/preflight/preflight.py scan …`

It currently recognizes:

- SBPL signature `deny_message_filter` (witness-backed but still treated as **partial** for generality), and
- `.sb.bin` exact digest membership (`apply_gate_blob_digest`) sourced from a checked-in digest corpus (status **ok** as an exact-match avoidance mechanism on this world; see below).

<details>
<summary>Preflight prevents evidence laundering (forced vs default)</summary>

Same input SBPL (`W/mach_bootstrap_deny_message_send/minimal_failing.sb`), observed through the runtime harness’s normalized `runtime_result` shape:

Default/preflight-enforced run:

```json
{
  "status": "blocked",
  "failure_stage": "preflight",
  "failure_kind": "preflight_apply_gate_signature",
  "apply_report": null,
  "errno": null
}
```

Forced apply run (explicit opt-out of the guardrail):

```json
{
  "status": "errno",
  "failure_stage": "apply",
  "failure_kind": "sandbox_init_failed",
  "apply_report": {
    "api": "sandbox_init",
    "rc": -1,
    "errno": 1,
    "errbuf": "Operation not permitted",
    "err_class": "errno_eperm",
    "err_class_source": "errno_only"
  },
  "errno": 1
}
```

This is the operational safety win: the default path produces a “blocked at preflight” record rather than manufacturing an apply-stage EPERM failure that downstream tooling might misread as a decision-stage deny.

</details>

### Digest corpus for compiled blobs (exact-match avoidance)

To extend preflight beyond `.sb` (where structural scanning is possible) to `.sb.bin`, we built a digest corpus of compiled blobs confirmed to be apply-gated on this world:

- Experiment: [`book/experiments/preflight-blob-digests/`](../../book/experiments/preflight-blob-digests/)
- Validation IR consumed by the preflight tool: [`book/graph/concepts/validation/out/experiments/preflight-blob-digests/blob_digests_ir.json`](../../book/graph/concepts/validation/out/experiments/preflight-blob-digests/blob_digests_ir.json)
- Human-facing digest list (experiment output): [`book/experiments/preflight-blob-digests/out/apply_gate_blob_digests.json`](../../book/experiments/preflight-blob-digests/out/apply_gate_blob_digests.json)

This is intentionally an avoidance mechanism, not a semantic classifier. It is robust because it does not guess: it only matches exact digests that are already witnessed.

The same experiment records an important meta-lesson: there exist harness contexts where apply is **globally gated** (even control blobs fail). Digest evidence is only meaningful when recorded in a control-ok context; this is why the experiment carries control digests and an apply matrix that distinguishes “global gate” from “profile-specific gate”.

### SBPL-wrapper integration (make the safe behavior the default)

SBPL-wrapper now runs preflight as an operational guardrail by default and emits an explicit `tool:"sbpl-preflight"` marker:

- Wrapper: [`book/tools/sbpl/wrapper/wrapper.c`](../../book/tools/sbpl/wrapper/wrapper.c)
- Docs: [`book/tools/sbpl/wrapper/README.md`](../../book/tools/sbpl/wrapper/README.md)

By default (`--preflight enforce`), the wrapper will short-circuit before attempting apply when preflight recognizes a known apply-gate signature. This prevents “hypothesis evidence” from being accidentally laundered into “deny evidence” by downstream tooling.

Experiments that *must* observe apply-gated behavior explicitly opt out with `--preflight force`.

### Repo-wide index (artifact-driven profile selection)

To reduce future agent friction, we also check in a repo-wide “enterability manifest” derived from preflight scanning of in-repo profile inputs:

- Provenance (archived): [`book/experiments/archive/preflight-index/Report.md`](../../book/experiments/archive/preflight-index/Report.md)
- Manifest: [`book/tools/preflight/index/preflight_enterability_manifest.json`](../../book/tools/preflight/index/preflight_enterability_manifest.json)
- Summary: [`book/tools/preflight/index/summary.json`](../../book/tools/preflight/index/summary.json)

Operational invariant for agents:

> Prefer profiles with `classification == "no_known_apply_gate_signature"` unless the task is explicitly about apply gates.

This is intentionally phrased as “avoid known dead ends,” not “guarantee success.”

### Reusable pattern

- Make phase classification mechanical (markers + normalizer), so “EPERM” can’t collapse into a single meaning.
- Delta-debug to a minimal failing/passing neighbor pair, so the gate is a boundary object rather than a story.
- Capture bounded forensics with controls (failing and passing windows), so causal chains can be audited.
- Add conservative preflight/digest guardrails, so agents avoid known dead ends by default.
- Add regression tests so the phase meaning and guardrails cannot silently regress.

## Enforcement

This resolution is enforced in three places:

- **Wrapper-level default**: SBPL-wrapper’s default `--preflight enforce` makes “don’t attempt known-gated applies” the default behavior, and `--preflight force` makes “I am intentionally studying the gate” an explicit choice (see [`book/tools/sbpl/wrapper/README.md`](../../book/tools/sbpl/wrapper/README.md)).
- **Normalized runtime IR**: the runtime harness emits `failure_stage:"preflight"` / `failure_kind:"preflight_apply_gate_signature"` instead of generating an apply-stage EPERM record when it is knowingly entering an apply-gated category (see [`book/api/runtime/execution/harness/runner.py`](../../book/api/runtime/execution/harness/runner.py)). This protects semantic tallies from being polluted by hypothesis evidence.
- **Regression tests**: basic guardrails ensure that preflight + wrapper integration stays mechanically visible and doesn’t regress back into substring inference:
  - [`book/tests/test_sbpl_wrapper_preflight.py`](../../book/tests/test_sbpl_wrapper_preflight.py)
  - [`book/tests/test_runtime_tools_component_preflight.py`](../../book/tests/test_runtime_tools_component_preflight.py)

## Current status (what we know, what remains open)

**What we consider settled enough to operationalize (mapped / status ok where noted)**

- Apply-stage `EPERM` is a Profile lifecycle failure (hypothesis evidence), and our tooling keeps it mechanically distinct from policy decisions.
- Across the validated witness set, the minimal failing SBPLs all contain deny-style `apply-message-filter` rules, and the micro-variant matrix shows deny-style variants apply-gate while at least some allow-style variants successfully apply; this supports the narrow trigger story “deny-style message filtering is gated for this harness identity on this world” (see section 4 + the Witness Summary Table + Appendix witness bundles).
- Across the validated witness set, compilation succeeds and `sandbox_apply` is the failing step observed (`errno==EPERM` at apply stage) on this world and under this harness identity (see section 5 + the Witness Summary Table + Appendix witness bundles).
- Across the validated witness set, the unified log includes the reason string “missing message filter entitlement” during the bounded failing-apply window while the applying process’s effective entitlement marker reports `com.apple.private.security.message-filter` absent; this is correlation evidence, not a sufficiency proof without a positive control (see section 6 + Appendix witness bundles).
- We have durable guardrails (preflight + wrapper integration + digest corpus + index manifest) that prevent accidental re-learning.

**What remains intentionally not closed (still unknown / not upgraded to bedrock)**

- We do not have a positive-control demonstration that adding the entitlement to the harness identity makes the same profiles apply successfully (this may be infeasible on this host baseline).
- We have not promoted a general structural classifier for `.sb.bin` beyond exact digest match; “structural signal listening” remains explicitly partial/brittle in [`book/experiments/preflight-blob-digests/Report.md`](../../book/experiments/preflight-blob-digests/Report.md).
- We have not fully localized the kernel-side enforcement logic beyond xref-level static hints; the runtime claim is grounded in the log trace + entitlement markers, not in a blessed “this is the one validator” reverse-engineering result.

## Pointers

### Primary “apply gate” explanation surfaces

- [`troubles/EPERM_chasing.md`](../../troubles/EPERM_chasing.md) — earliest “system blobs fail apply” writeup (historical; paths may be stale).
- [`troubles/EPERMx2.md`](../../troubles/EPERMx2.md) — phase taxonomy and current discipline; includes pointers to many affected experiments.
- [`status/EPERM/apply-gate.md`](apply-gate.md) — this consolidated record.

### Tools / API surfaces

- SBPL apply harness: [`book/tools/sbpl/wrapper/wrapper.c`](../../book/tools/sbpl/wrapper/wrapper.c), [`book/tools/sbpl/wrapper/README.md`](../../book/tools/sbpl/wrapper/README.md)
- Runtime marker/contract layer: [`book/api/runtime/native/tool_markers.h`](../../book/api/runtime/native/tool_markers.h), [`book/api/runtime/contracts/schema.py`](../../book/api/runtime/contracts/schema.py)
- Preflight tooling: [`book/tools/preflight/`](../../book/tools/preflight/)

### Experiments that produced the current understanding

- Witness corpus + cause tightening:
  - [`book/experiments/gate-witnesses/Report.md`](../../book/experiments/gate-witnesses/Report.md)
  - Validation output: [`book/graph/concepts/validation/out/experiments/gate-witnesses/witness_results.json`](../../book/graph/concepts/validation/out/experiments/gate-witnesses/witness_results.json)
  - Forensics (compiled blobs + unified logs): [`book/graph/concepts/validation/out/experiments/gate-witnesses/forensics/`](../../book/graph/concepts/validation/out/experiments/gate-witnesses/forensics)
- `.sb.bin` digest-based avoidance:
  - [`book/experiments/preflight-blob-digests/Report.md`](../../book/experiments/preflight-blob-digests/Report.md)
  - Validation IR: [`book/graph/concepts/validation/out/experiments/preflight-blob-digests/blob_digests_ir.json`](../../book/graph/concepts/validation/out/experiments/preflight-blob-digests/blob_digests_ir.json)
- Repo-wide enterability manifest:
  - [`book/experiments/archive/preflight-index/Report.md`](../../book/experiments/archive/preflight-index/Report.md)
  - Manifest: [`book/tools/preflight/index/preflight_enterability_manifest.json`](../../book/tools/preflight/index/preflight_enterability_manifest.json)

## Appendix: Witness bundles (per witness)

<details>
<summary>`airlock` witness bundle</summary>

Paths:

- SBPL pair: `W/airlock/minimal_failing.sb`, `W/airlock/passing_neighbor.sb`
- Compiled blobs: `F/airlock/minimal_failing.sb.bin`, `F/airlock/passing_neighbor.sb.bin`
- Logs: `F/airlock/log_show_primary.minimal_failing.txt`, `F/airlock/log_show_primary.passing_neighbor.txt`

Unified log line (from `F/airlock/log_show_primary.minimal_failing.txt`):

```text
2025-12-19 11:06:53.727924-0800  localhost kernel[0]: (Sandbox) wrapper[3331]: missing message filter entitlement
```

Compile marker (from `R`, `witnesses[target=="airlock"].forensics.compile.minimal_failing.marker`):

```json
{"bytecode_length":513,"errbuf":null,"errno":0,"marker_schema_version":1,"profile_type":0,"rc":0}
```

Apply report (from `R`, `…forensics.blob_apply.minimal_failing`):

```json
{"failure_stage":"apply","failure_kind":"sandbox_apply_failed","apply_report":{"api":"sandbox_apply","rc":-1,"errno":1,"errbuf":"Operation not permitted","err_class":"errno_eperm","err_class_source":"errno_only"}}
```

Entitlement marker (from `R`, `…forensics.blob_apply.minimal_failing.entitlement_checks[0]`):

```json
{"tool":"entitlement-check","marker_schema_version":1,"stage":"pre_apply","entitlement":"com.apple.private.security.message-filter","pid":3331,"rc":0,"present":false,"value_type":"absent"}
```

</details>

<details>
<summary>`blastdoor` witness bundle</summary>

Paths:

- SBPL pair: `W/blastdoor/minimal_failing.sb`, `W/blastdoor/passing_neighbor.sb`
- Compiled blobs: `F/blastdoor/minimal_failing.sb.bin`, `F/blastdoor/passing_neighbor.sb.bin`
- Logs: `F/blastdoor/log_show_primary.minimal_failing.txt`, `F/blastdoor/log_show_primary.passing_neighbor.txt`

Unified log line (from `F/blastdoor/log_show_primary.minimal_failing.txt`):

```text
2025-12-19 11:06:54.672919-0800  localhost kernel[0]: (Sandbox) wrapper[3341]: missing message filter entitlement
```

Compile marker (from `R`, `witnesses[target=="blastdoor"].forensics.compile.minimal_failing.marker`):

```json
{"bytecode_length":448,"errbuf":null,"errno":0,"marker_schema_version":1,"profile_type":0,"rc":0}
```

Apply report (from `R`, `…forensics.blob_apply.minimal_failing`):

```json
{"failure_stage":"apply","failure_kind":"sandbox_apply_failed","apply_report":{"api":"sandbox_apply","rc":-1,"errno":1,"errbuf":"Operation not permitted","err_class":"errno_eperm","err_class_source":"errno_only"}}
```

Entitlement marker (from `R`, `…forensics.blob_apply.minimal_failing.entitlement_checks[0]`):

```json
{"tool":"entitlement-check","marker_schema_version":1,"stage":"pre_apply","entitlement":"com.apple.private.security.message-filter","pid":3341,"rc":0,"present":false,"value_type":"absent"}
```

</details>

<details>
<summary>`com.apple.CoreGraphics.CGPDFService` witness bundle</summary>

Paths:

- SBPL pair: `W/com.apple.CoreGraphics.CGPDFService/minimal_failing.sb`, `W/com.apple.CoreGraphics.CGPDFService/passing_neighbor.sb`
- Compiled blobs: `F/com.apple.CoreGraphics.CGPDFService/minimal_failing.sb.bin`, `F/com.apple.CoreGraphics.CGPDFService/passing_neighbor.sb.bin`
- Logs: `F/com.apple.CoreGraphics.CGPDFService/log_show_primary.minimal_failing.txt`, `F/com.apple.CoreGraphics.CGPDFService/log_show_primary.passing_neighbor.txt`

Unified log line (from `F/com.apple.CoreGraphics.CGPDFService/log_show_primary.minimal_failing.txt`):

```text
2025-12-19 11:06:55.200211-0800  localhost kernel[0]: (Sandbox) wrapper[3353]: missing message filter entitlement
```

Compile marker (from `R`, `witnesses[target=="com.apple.CoreGraphics.CGPDFService"].forensics.compile.minimal_failing.marker`):

```json
{"bytecode_length":513,"errbuf":null,"errno":0,"marker_schema_version":1,"profile_type":0,"rc":0}
```

Apply report (from `R`, `…forensics.blob_apply.minimal_failing`):

```json
{"failure_stage":"apply","failure_kind":"sandbox_apply_failed","apply_report":{"api":"sandbox_apply","rc":-1,"errno":1,"errbuf":"Operation not permitted","err_class":"errno_eperm","err_class_source":"errno_only"}}
```

Entitlement marker (from `R`, `…forensics.blob_apply.minimal_failing.entitlement_checks[0]`):

```json
{"tool":"entitlement-check","marker_schema_version":1,"stage":"pre_apply","entitlement":"com.apple.private.security.message-filter","pid":3353,"rc":0,"present":false,"value_type":"absent"}
```

</details>

<details>
<summary>`mach_bootstrap_deny_message_send` witness bundle</summary>

Paths:

- SBPL pair: `W/mach_bootstrap_deny_message_send/minimal_failing.sb`, `W/mach_bootstrap_deny_message_send/passing_neighbor.sb`
- Compiled blobs: `F/mach_bootstrap_deny_message_send/minimal_failing.sb.bin`, `F/mach_bootstrap_deny_message_send/passing_neighbor.sb.bin`
- Logs: `F/mach_bootstrap_deny_message_send/log_show_primary.minimal_failing.txt`, `F/mach_bootstrap_deny_message_send/log_show_primary.passing_neighbor.txt`

Unified log line (from `F/mach_bootstrap_deny_message_send/log_show_primary.minimal_failing.txt`):

```text
2025-12-19 11:06:55.686235-0800  localhost kernel[0]: (Sandbox) wrapper[3363]: missing message filter entitlement
```

Compile marker (from `R`, `witnesses[target=="mach_bootstrap_deny_message_send"].forensics.compile.minimal_failing.marker`):

```json
{"bytecode_length":473,"errbuf":null,"errno":0,"marker_schema_version":1,"profile_type":0,"rc":0}
```

Apply report (from `R`, `…forensics.blob_apply.minimal_failing`):

```json
{"failure_stage":"apply","failure_kind":"sandbox_apply_failed","apply_report":{"api":"sandbox_apply","rc":-1,"errno":1,"errbuf":"Operation not permitted","err_class":"errno_eperm","err_class_source":"errno_only"}}
```

Entitlement marker (from `R`, `…forensics.blob_apply.minimal_failing.entitlement_checks[0]`):

```json
{"tool":"entitlement-check","marker_schema_version":1,"stage":"pre_apply","entitlement":"com.apple.private.security.message-filter","pid":3363,"rc":0,"present":false,"value_type":"absent"}
```

</details>
