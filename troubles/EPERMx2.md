# EPERM x2: “Operation not permitted” at multiple layers

## Context

- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (baseline: [`book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`](book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)).
- This repo uses multiple runtime harnesses (`sandbox-exec`, SBPL-wrapper, Swift/Python runners). Across those, `EPERM` shows up in at least three different phases.
- This note is a collector and a taxonomy: it tries to stop us from treating every `EPERM` as “the sandbox denied the operation”, when sometimes it means “the profile never installed” or “the harness never executed”.

## Broad summary

On this host baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`), “Operation not permitted” (`EPERM`) is not treated as a single semantic signal. In SANDBOX_LORE, the same string can arise in different phases of the profile lifecycle, and conflating them produces false “the sandbox denied X” stories. The EPERMx2 framing separates (a) apply-stage failures where a Profile never becomes part of the process label, (b) decision-stage denies where a PolicyGraph actually evaluates an Operation+Filter and returns a deny Decision, (c) harness/bootstrap failures where the probe never becomes a runnable process under the intended policy, and (d) libsandbox API/entitlement-layer failures that are not PolicyGraph decisions at all. This distinction is part of the repo’s evidence discipline: apply gates are “blocked” evidence, decision outcomes can be “mapped-but-partial”, and only static structure claims are candidates for bedrock status.

Apply-stage EPERM (“apply gate”) means the attempt to install a profile fails at `sandbox_init` (SBPL text) or `sandbox_apply` (compiled blob), so no PolicyGraph evaluation for the intended probe can have occurred. This is visible in wrapper-level errors like `sandbox_init failed: Operation not permitted` or `sandbox_apply: Operation not permitted`, and it is treated as an environment constraint rather than a denial of any particular Operation. On this world, platform/system profiles (notably `sys:airlock`) repeatedly exhibit apply-stage EPERM even when sourced from SBPL, and this is recorded as a first-class limitation in the runtime-checks narrative and in mapping/validation summaries that label runtime slices “blocked” when applies fail. The key status point is that an apply-stage EPERM is not counted as runtime evidence about an Operation, Filter, or PolicyGraph path; it is evidence that the harness could not enter the intended policy state on this host.

Decision-stage EPERM occurs after successful apply and shows up as syscall-level denials like `open target: Operation not permitted` (as opposed to wrapper apply errors), meaning an Operation was attempted under an installed profile and the effective policy stack returned a deny. This is the EPERM that supports semantic claims, and it appears in the golden runtime artifacts (e.g., the golden-triple runtime results) and in bounded semantic experiments like vfs-canonicalization and runtime-adversarial. In those experiments, decision-stage EPERMs are used to articulate narrow, host-specific stories (for example, `/tmp` vs `/private/tmp` behavior for `file-read*`/`file-write*`) while keeping scope explicit. The metadata-runner work further emphasizes the need for classification: it records apply success (`apply_rc=0`) alongside EPERM returns from metadata syscalls, showing that alias/canonical behavior can differ across operation families and syscall choices without invoking apply gating. Overall, decision-stage EPERM evidence in this repo is intentionally narrow (anchored to specific scenarios and a small set of operations with runtime backing) and is not silently generalized into a global “the sandbox does X” claim.

Harness-layer EPERM (and related abort-style outcomes) is treated as a separate class: failures like `sandbox-exec: execvp() … failed: Operation not permitted` and SIGABRT/exit -6 events reflect bootstrap viability under modern State constraints rather than clean policy decisions, and they are kept distinct from both apply gates and decision-stage denies. There is also an API/entitlement-layer EPERM pattern that is explicitly not a PolicyGraph decision at all, exemplified by extension issuance behavior where libsandbox APIs can yield “success-ish” return codes but still produce `errno=EPERM` and unusable tokens; this is treated as an entitlement/provenance gate on the API surface, not as an Operation denial in the applied policy. Status-wise, the repo’s bedrock claim remains the static identity and decoded structure of canonical system blobs (e.g., [`book/graph/mappings/system_profiles/digests.json`](book/graph/mappings/system_profiles/digests.json) entries with `status: ok`), while runtime semantics are explicitly partial and apply-gated episodes remain blocked. Where older narratives, planning notes, or experiment reports drift from current artifacts (paths, stated capabilities, or mismatch explanations), that inconsistency is recorded rather than “resolved” by blending stories, preserving the boundary between what is structurally known and what is semantically demonstrated on this host.

## SBPL-wrapper as the classification anchor

[`book/tools/sbpl/wrapper/wrapper.c`](book/tools/sbpl/wrapper/wrapper.c) is the repo’s smallest “apply surface” for runtime probes: it takes either SBPL text (`--sbpl <profile.sb>`) and calls `sandbox_init`, or a compiled blob (`--blob <profile.sb.bin>`) and calls `sandbox_apply`, applies that Profile to the current process, then `execvp`s the target command. This gives us a single choke-point where we can observe whether we ever reached the “policy installed” stage, separately from whether we successfully bootstrapped a probe process.

To make this classification mechanically robust (not substring-fragile), the wrapper now emits one JSONL marker per phase on stderr with `tool:"sbpl-apply"` and a `stage` such as `apply`, `applied`, or `exec` (alongside the existing human-readable stderr). Consumers should classify outcomes using these markers, not by matching localized error strings. In particular: an `apply` marker with `rc != 0` is an apply-stage failure (**blocked**); an `exec` marker after `applied` with `errno == EPERM` is best treated as a distinct “bootstrap deny” bucket (e.g. process-exec blocked under the applied policy stack), not as generic harness weirdness; and “no wrapper-stage failure marker” only means “the wrapper didn’t see a failure”. It does **not** by itself prove that any later syscall `EPERM` is a Seatbelt/PolicyGraph deny, since `EPERM` can also originate from adjacent layers or ordinary filesystem semantics.

## Taxonomy (EPERM²)

### 1) Apply-stage EPERM (“apply gate”) — **blocked**

**What it is:** applying SBPL or a compiled blob fails up front (`sandbox_init` or `sandbox_apply`), so the process never runs under the intended policy.

**Telltales:**
- SBPL-wrapper prints:
  - `sandbox_init failed: Operation not permitted`
  - `sandbox_apply: Operation not permitted`
- In normalized IR, this often appears as a probe that is recorded as `deny` with notes/stderr containing the wrapper’s apply error.

**Evidence / scope on this world (mapped-but-partial / blocked):**
- Platform/system apply gates are a recurring constraint in docs and experiments; treat these outcomes as environment evidence, not as “missing profiles” (see [`guidance/Preamble.md`](guidance/Preamble.md) and [`book/tools/sbpl/wrapper/README.md`](book/tools/sbpl/wrapper/README.md)).
- There are *at least two shapes* of apply-stage EPERM in the repo today:
  1) **Profile-specific apply gate**: `airlock` fails apply on this host even when recompiled from SBPL (see [`troubles/EPERM_chasing.md`](troubles/EPERM_chasing.md), [`book/experiments/golden-corpus/Report.md`](book/experiments/golden-corpus/Report.md), and runtime-checks notes in [`book/experiments/runtime-checks/Notes.md`](book/experiments/runtime-checks/Notes.md)).
  2) **Environment/harness apply gate**: some historical runs record `sandbox_init` returning EPERM for *everything* (see “blocked runtime vocab usage” in [`book/graph/concepts/validation/out/vocab/runtime_usage.json`](book/graph/concepts/validation/out/vocab/runtime_usage.json) and the early runtime-checks chronology in [`book/experiments/runtime-checks/Notes.md`](book/experiments/runtime-checks/Notes.md)). It is not yet clear which parts of that story were host State vs harness context drift (see “Drift / inconsistencies” below).

### 2) Decision-stage EPERM (“deny decision”) — **mapped-but-partial**

**What it is:** the profile applied successfully; later, a probed operation is denied and the syscall returns `EPERM`.

**Telltales:**
- Probe stderr like `open target: Operation not permitted` / `cat: … Operation not permitted` (not `sandbox_apply:` / `sandbox_init failed:`).
- Control runs under permissive profiles succeed (distinguishing policy denial from basic filesystem perms).

**Representative sources:**
- Golden-triple runtime stderr examples: [`book/profiles/golden-triple/runtime_results.json`](book/profiles/golden-triple/runtime_results.json).
- VFS canonicalization mismatches present as decision-stage `EPERM` (“open target”) even when the SBPL *looks* like it should allow (see [`book/experiments/vfs-canonicalization/Report.md`](book/experiments/vfs-canonicalization/Report.md) and [`book/experiments/runtime-adversarial/Report.md`](book/experiments/runtime-adversarial/Report.md)).
- Metadata runner explicitly distinguishes apply success (`apply_rc=0`) from syscall EPERMs on alias paths (see [`book/experiments/metadata-runner/EPERM.md`](book/experiments/metadata-runner/EPERM.md)).

### 3) Harness-layer EPERM (bootstrap/exec failure) — **partial**

**What it is:** the harness fails before we can observe the intended Operation+Filter behavior (e.g., `sandbox-exec` can’t `execvp` the probe binary under a restrictive Profile).

**Telltales:**
- `sandbox-exec: execvp() of 'cat' failed: Operation not permitted`
- exit codes like 71 with empty/odd probe output, or SIGABRT/exit -6 due to loader starvation rather than a clean deny decision.

**Representative source:**
- [`troubles/sandbox-exec_yolo.md`](troubles/sandbox-exec_yolo.md)

### 4) API/entitlement-layer EPERM (not an Operation decision) — **resolved/understood limitation**

**What it is:** a libsandbox API returns a confusing “success-ish” code path but still sets `errno=EPERM` (e.g., extension issuance returning `rc=0` with `token=NULL`).

**Representative source:**
- [`troubles/extensions_demo_Nov26.md`](troubles/extensions_demo_Nov26.md)

## Reproduction (minimal, to classify an EPERM quickly)

These are *classification* repros: the point is to see whether the failure is apply-stage (`sandbox_init`/`sandbox_apply`) or later (decision/harness).

- Build the wrapper once (see [`book/tools/sbpl/wrapper/README.md`](book/tools/sbpl/wrapper/README.md)):
  - `cd book/tools/sbpl/wrapper && clang -Wall -Wextra -o wrapper wrapper.c -lsandbox -framework Security -framework CoreFoundation`
- Control: a known-good custom blob should apply and then `execvp`:
  - `book/tools/sbpl/wrapper/wrapper --blob book/profiles/golden-triple/allow_all.sb.bin -- /usr/bin/true`
- Apply-stage EPERM (profile-specific gate witness): `airlock` SBPL text:
  - `book/tools/sbpl/wrapper/wrapper --sbpl /System/Library/Sandbox/Profiles/airlock.sb -- /usr/bin/true`
  - Expect: `sandbox_init failed: Operation not permitted`
- Apply-stage EPERM (blob mode): canonical `airlock` blob from fixtures:
  - `book/tools/sbpl/wrapper/wrapper --blob book/graph/concepts/validation/fixtures/blobs/airlock.sb.bin -- /usr/bin/true`
  - Expect: `sandbox_apply: Operation not permitted`

## Bedrock vs partial vs blocked (so we don’t silently upgrade claims)

- **Bedrock (static structure)**: canonical system profile blobs and their contracts are `status: ok` in [`book/graph/mappings/system_profiles/digests.json`](book/graph/mappings/system_profiles/digests.json). This is a claim about the blobs’ identity and decoded structure, not runtime behavior (see the “where the claim stops” discussion in [`status/first-promotion/post-remediation.md`](status/first-promotion/post-remediation.md)).
  - Canonical blob sources are under `book/graph/concepts/validation/fixtures/blobs/` (e.g., `.../airlock.sb.bin`, `.../bsd.sb.bin`) as recorded by the `source` fields in the digests mapping.
- **Mapped-but-partial (runtime semantics)**: golden runtime scenarios, VFS canonicalization, and some adversarial families are backed by runtime artifacts, but scope is narrow and some runs carry known environment caveats (see [`status/second-report/test-coverage.md`](status/second-report/test-coverage.md)).
- **Blocked**: any “runtime story” inferred from an apply-stage EPERM is blocked by definition; the profile did not install, so the would-be PolicyGraph was not evaluated for that probe.

## Apply-gate: deny-style message filtering (current evidence)

This repo now has a small, mechanical witness corpus that ties a common apply-stage EPERM to deny-style message filtering, and it includes a direct, host-grounded “why” trace from the unified log.

- **Minimized witnesses (blocked, but confirmed)**: `book/experiments/gate-witnesses/` produces regression-checked witness pairs for three system profiles (`airlock`, `blastdoor`, `com.apple.CoreGraphics.CGPDFService`). All three minimize to the same failing SBPL shape:
  - `(allow iokit-open-user-client (apply-message-filter (deny iokit-external-method)))`
  - Example: [`book/experiments/gate-witnesses/out/witnesses/airlock/minimal_failing.sb`](book/experiments/gate-witnesses/out/witnesses/airlock/minimal_failing.sb)
  - Confirmation distributions (e.g. `--confirm 10`) are recorded per target in the checked-in `run.json` (example: [`book/experiments/gate-witnesses/out/witnesses/airlock/run.json`](book/experiments/gate-witnesses/out/witnesses/airlock/run.json)).
  - Status: these are “blocked evidence” about runtime semantics (the Profile never attaches), but they are durable boundary objects.
- **Compile-vs-apply split (partial)**: `book/experiments/gate-witnesses/out/compile_vs_apply.json` shows the failing witnesses compile successfully (via `sandbox_compile_file`) but fail at apply time (`sandbox_apply` returns `EPERM`). On this host, this is evidence that the gate is enforced at apply/attach time, not as a compiler rejection.
- **Unified log enforcement trace (partial, high-signal)**: the gate-witnesses validation job captures a kernel log line that directly states the failure reason for the wrapper process:
  - Example: [`book/graph/concepts/validation/out/experiments/gate-witnesses/forensics/airlock/log_show_primary.minimal_failing.txt`](book/graph/concepts/validation/out/experiments/gate-witnesses/forensics/airlock/log_show_primary.minimal_failing.txt) contains `missing message filter entitlement`.
  - This is host-grounded runtime evidence that the apply-stage EPERM is an entitlement-gated capability, not a generic “sandbox denied operation X” outcome.
- **Non-IOKit scope witness (blocked, confirmed)**: `book/experiments/gate-witnesses/` includes a minimized, confirmed witness pair demonstrating that deny-style message filtering gates outside IOKit as well (under `mach-bootstrap`):
  - Minimal failing SBPL: [`book/experiments/gate-witnesses/out/witnesses/mach_bootstrap_deny_message_send/minimal_failing.sb`](book/experiments/gate-witnesses/out/witnesses/mach_bootstrap_deny_message_send/minimal_failing.sb)
  - Passing neighbor: [`book/experiments/gate-witnesses/out/witnesses/mach_bootstrap_deny_message_send/passing_neighbor.sb`](book/experiments/gate-witnesses/out/witnesses/mach_bootstrap_deny_message_send/passing_neighbor.sb)
  - Confirm distribution: [`book/experiments/gate-witnesses/out/witnesses/mach_bootstrap_deny_message_send/run.json`](book/experiments/gate-witnesses/out/witnesses/mach_bootstrap_deny_message_send/run.json)

## Operational guidance (avoid dead-end applies)

These are practical “don’t waste cycles” constraints derived from the current witnesses on this world.

- Treat any apply-stage `EPERM` (`sandbox_init`/`sandbox_apply` failing) as **blocked**: do not write probes that interpret it as an Operation+Filter denial. In normalized runtime IR, it should be a `failure_stage:"apply"` outcome with an `apply_report` (this prevents downstream “deny inflation”).
- When you can choose profile shapes, avoid deny-style message filtering under `apply-message-filter` in harness-applied profiles. Today the smallest known triggers include deny payloads for:
  - `iokit-external-method` / `iokit-async-external-method` / `iokit-external-trap` (minimized witnesses), and
  - `mach-message-send` (minimized non-IOKit scope witness).
- If apply succeeds but `execvp` fails with `EPERM`, classify it as a bootstrap failure *under the applied policy* (not as “environment weirdness”): it may reflect a `process-exec*` deny preventing the probe from ever running.
- Before attempting to apply a profile from a runner/tool, use the static preflight tool:
  - `python3 book/tools/preflight/preflight.py scan <profile.sb>`
  - If it reports `likely_apply_gated_for_harness_identity`, treat the profile as “not enterable by harness identity on this world” unless you are explicitly studying apply gates.
  - This preflight is conservative and host-scoped (witness-backed but still “partial” as a universal rule); absence of a signature is not a guarantee that apply will succeed.

## Tooling resolution (avoid re-learning apply gating)

- `book/tools/preflight/` is the canonical operational avoidance tool for known apply-gate signatures (deny-style message filtering today).
- `book/tools/preflight/index/preflight_enterability_manifest.json` is a checked-in, repo-wide inventory of preflight classifications over in-repo profile inputs (use it as an artifact-driven “pick from the no-known-signature set” aid).
- `book/api/runtime_harness/runner.py` runs this preflight for SBPL (`.sb`) and compiled SBPL blobs (`.sb.bin`) and, when blocked, emits `failure_stage:"preflight"` / `failure_kind:"preflight_apply_gate_signature"` instead of attempting an apply that would fail at `sandbox_init`/`sandbox_apply`.
- This is a tooling choice to preserve the repo’s evidence discipline: it prevents accidental “EPERM means deny” stories when a Profile never attached.

## Evidencing gaps (what a reasonable critic could demand)

- Beyond exact digest match: discover a structural signal (if one exists) that correlates with the current apply-gate witness set, so preflight can be extended without growing an unbounded digest list.

## Drift / inconsistencies to record (do not resolve by “averaging stories”)

- [`troubles/EPERM_chasing.md`](troubles/EPERM_chasing.md) points at now-stale blob locations (`book/examples/extract_sbs/build/profiles/…`). Canonical system blobs are now referenced as `book/graph/concepts/validation/fixtures/blobs/{airlock,bsd,sample}.sb.bin` in [`book/graph/mappings/system_profiles/digests.json`](book/graph/mappings/system_profiles/digests.json).
- [`book/tools/sbpl/wrapper/Plan.md`](book/tools/sbpl/wrapper/Plan.md) says blob-mode is TODO, but [`book/tools/sbpl/wrapper/wrapper.c`](book/tools/sbpl/wrapper/wrapper.c) already implements `--blob` via `sandbox_apply`.
- Runtime-adversarial has internal tension between narrative and artifacts:
  - The report frames key mismatches as VFS canonicalization, but `out/mismatch_summary.json` contains many entries annotated with `notes: "sandbox_apply: Operation not permitted\n"` (apply-stage failure marker) (see [`book/experiments/runtime-adversarial/Report.md`](book/experiments/runtime-adversarial/Report.md) vs [`book/experiments/runtime-adversarial/out/mismatch_summary.json`](book/experiments/runtime-adversarial/out/mismatch_summary.json)).
- VFS canonicalization runtime outputs include a note about being captured under a more permissive “Codex harness `--yolo`” environment to clear a prior apply gate (see [`book/experiments/vfs-canonicalization/Notes.md`](book/experiments/vfs-canonicalization/Notes.md) and [`book/experiments/vfs-canonicalization/Report.md`](book/experiments/vfs-canonicalization/Report.md)). This is a reminder that *harness context* can change whether apply succeeds, and should be recorded explicitly whenever it matters.

## Pointers (where to look next)

### Primary apply-gate collectors

- [`troubles/EPERM_chasing.md`](troubles/EPERM_chasing.md) — initial “system blobs fail apply” writeup (stale paths; narrow framing).
- [`troubles/profile_blobs.md`](troubles/profile_blobs.md) — broader blob-apply history, wrapper wiring, and header observations (includes hypotheses; treat as partial).
- [`book/tools/sbpl/wrapper/README.md`](book/tools/sbpl/wrapper/README.md) and [`book/tools/sbpl/wrapper/wrapper.c`](book/tools/sbpl/wrapper/wrapper.c) — the concrete apply surface (`sandbox_init` vs `sandbox_apply`) used by many runtime probes.
- [`book/experiments/runtime-checks/Notes.md`](book/experiments/runtime-checks/Notes.md) — chronology showing both “global apply gate” and “platform/profile apply gate” episodes.

### Places apply-stage EPERM is recorded in normalized IR/mappings

- [`book/graph/mappings/runtime_cuts/scenarios.json`](book/graph/mappings/runtime_cuts/scenarios.json) and [`book/graph/mappings/runtime_cuts/runtime_story.json`](book/graph/mappings/runtime_cuts/runtime_story.json) — mapping-layer slices containing `stderr: "sandbox_apply: Operation not permitted\n"` entries.
- [`book/experiments/op-coverage-and-runtime-signatures/out/runtime_mappings/traces/`](book/experiments/op-coverage-and-runtime-signatures/out/runtime_mappings/traces/) — per-scenario JSONL traces that often include wrapper stderr.

### Decision-stage EPERM (policy denials) references

- [`book/profiles/golden-triple/runtime_results.json`](book/profiles/golden-triple/runtime_results.json) — runtime triples with `open target: Operation not permitted` stderr.
- [`book/experiments/metadata-runner/EPERM.md`](book/experiments/metadata-runner/EPERM.md) — explicitly “not an apply gate” EPERMs (syscall-level) and alias-vs-canonical behavior.

## Status

- Status: **open / partial**.
- We have enough evidence to treat “EPERM” as a *family name* rather than a single phenomenon on this world, but we do not yet have a single, consistent accounting across:
  - “apply gates for platform/system profiles”,
  - “apply gates due to harness/environment context”,
  - “policy decision EPERM” for probed operations,
  - and “bootstrap failures” (sandbox-exec execvp, SIGABRT under strict profiles).
