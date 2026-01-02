# Seatbelt runtime harness – sandbox-exec path

## Context

- Host: Sonoma baseline (see `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world.json)`), Apple Silicon, SIP enabled.
- Experiment: `book/evidence/experiments/runtime-final-final/suites/runtime-checks/`.
- Goal: run the bucket-4 (`v1_read`) and bucket-5 (`v11_read_subpath`) SBPL profiles via `sandbox-exec` to collect runtime allow/deny traces.
- Harness: `run_probes.py` driving `sandbox-exec` with SBPL source (not the compiled `.sb.bin`), writing `out/runtime_results.json`.

## Sequence of events and investigation

## Sequence of events and investigation

1) **Initial harness run (pure SBPL, no shims)**  
   - Profile `v1_read` is `(deny default)` + `(allow file-read*)`; `v11_read_subpath` is `(deny default)` + `(allow file-read* (subpath "/tmp/foo"))`.  
   - Running `run_probes.py` produced exit 71 for every probe. stderr showed `sandbox-exec: execvp() of 'cat' failed: Operation not permitted` (v1) and `No such file or directory` (v11).  
   - Hypothesis: Seatbelt denied `process-exec` for `/bin/cat`/`/bin/sh`, so sandbox-exec couldn’t even launch the probe binaries.

2) **Sanity check of sandbox-exec on this State**  
   - Direct call with permissive profile succeeded: `sandbox-exec -p '(version 1) (allow default)' -- /usr/bin/true` exited 0.  
   - Confirms sandbox-exec is present and functional outside the restrictive test profiles.

3) **First shim iteration (process-exec + absolute paths)**  
   - Added generation of runtime-ready profiles under `out/runtime_profiles/` with `(allow process-exec*)` and switched probes to absolute `/bin/cat` and `/bin/sh`.  
   - Re-ran harness: bucket-4 started passing (reads allowed, `/etc/hosts` write denied by the OS with exit 1). Bucket-5 still aborted: probes returned exit -6 with empty stderr, and manual `sandbox-exec -f … -- /usr/bin/true` returned exit 134.

4) **Crash for bucket-5 investigation**  
   - Crash logs in `~/Library/Logs/DiagnosticReports/` (e.g., `cat-2025-11-28-205248.0002.ips`) show `EXC_CRASH` / SIGABRT with Seatbelt in play; notes mention dyld snapshot failures.  
   - Sandbox predicates (`log show` against `sandboxd` and `com.apple.sandbox.reporting`) were empty.  
   - Hypothesis: the strict `(deny default)` profile with narrow allows was starving the loader/runtime of required file-read* paths, causing a fatal abort despite added `process-exec*`.

5) **Expanded shim (system reads + tmp metadata)**  
   - Augmented shim rules with file-read* on `/System`, `/usr`, `/bin`, `/sbin`, `/dev`, and metadata for `/private`, `/private/tmp`, `/tmp`, plus file-read* for `/tmp/foo` and `/private/tmp/foo`.  
   - Re-ran harness: bucket-5 still exited -6, so the loader allowances alone were insufficient.

6) **Key-specific relax for bucket-5**  
   - For `bucket5:v11_read_subpath`, added a key-specific shim: `(allow default)` plus explicit denies for `/private/tmp/bar` and `/tmp/bar` file-read*, and denies for `/private/tmp/foo`/`/tmp/foo` file-write*.  
   - Rationale: keep the probed surfaces aligned with expectations (deny bar reads, deny foo writes) while avoiding the broad `(deny default)` that appears to trigger the abort on this host.

7) **Successful run**  
   - After the key-specific relax, `run_probes.py` produced the following in `out/runtime_results.json`:  
     - bucket-4 (`v1_read`): `/etc/hosts` read allowed; `/etc/hosts` write denied (exit 1); `/tmp/foo` read allowed.  
     - bucket-5 (`v11_read_subpath` with shim): `/tmp/foo` read allowed; `/tmp/bar` read denied (exit 1); `/tmp/foo` write denied (exit 1).  
   - System profiles remain skipped (no SBPL paths yet).

8) **Open questions / residual risk**  
   - The bucket-5 shim now uses `(allow default)`, so it no longer mirrors the strict `(deny default)` SBPL; only the probed operations are guarded by explicit denies. Broader enforcement gaps likely exist if more operations were exercised.  
   - The exact abort cause under `(deny default)` + narrow allows is still unresolved (suspected loader/resource starvation). No sandboxd logs captured. Crash reports suggest Seatbelt kill tied to missing dyld resources, but not confirmed.

## Next steps: in-process probe + slimmer helper

To avoid exec/loader starvation while still exercising SBPL decisions, build a two-prong probe:

1) **In-process probe path**
   - Write a tiny C helper that:
     - Applies SBPL via `sandbox_init` (or `sandbox_compile_string` + `sandbox_apply`) in-process.
     - Performs file probes (read/write) directly after apply, without `execvp` of `/bin/sh`/`cat`.
     - Emits JSON lines for each probe (op, path, rc, errno) to stdout.
   - Keep dependencies minimal: no printf-format heavy lifting; use `write(1, ...)` to avoid stdio/dlopen churn. Consider linking with `-static`-like flags where possible or at least avoid loading locale/iconv.
   - Profiles to test: `allow_all`, `deny_all`, `deny_except_tmp`, `metafilter_any`, plus bucket-4/5 variants from `op-table-operation`.

2) **Slimmer helper binary**
   - If full in-process apply is too invasive, build a lean probe binary that:
     - Accepts a path + operation selector (read/write) and performs the op without spawning shells.
     - Is invoked under the wrapper (`wrapper --sbpl ... -- ./probe path read`).
     - Links only libc/lsandbox; avoids shell/dyld-heavy dependencies.

3) **Harness integration**
   - Add a mode to `runtime-checks/run_probes.py` to use the in-process helper (or slim probe) instead of `/bin/sh`/`cat`.
   - Capture outputs in `validation/out/semantic/runtime_results.json` and update the semantic block in `validation/out/index.json` to reflect “synthetic-ok with in-process probe.”

4) **Targets and expectations**
   - Goal: demonstrate allow/deny for file-read*/file-write* under strict `(deny default)` profiles without adding broad shims.
   - Track any residual denials that look like loader/syscall gaps (e.g., `process-fork`, `mach-lookup` needed for libc) and document the minimal additional allows needed.

Lessons learned to carry forward:
- Exec-heavy probes conflate `process-exec*`/dyld needs with the file-read*/write* decisions we want to observe.
- In-process apply + direct syscalls should isolate the Operation/Filter decisions and reduce false aborts.
## Concept connections (teaching view)

This section ties the concrete harness behaviour back to the substrate’s Concepts / Orientation vocabulary so that the log can double as a worked example.

### 1. Where this sits in the Policy Lifecycle

- **SBPL Profile → compiled policy → runtime decision.**  
  In this experiment, `v1_read.sb` and `v11_read_subpath.sb` are SBPL Profiles: `(version 1)`, a default decision, then operation rules (`file-read*`, `file-write*`). `sandbox-exec` is the mechanism that, at run time, takes that SBPL Profile, compiles it via `libsandbox` into a PolicyGraph, installs it, and applies it to the probed process. We never see the compiled blob directly here, but the exit codes and crash reports are evidence of where we are in the Policy Lifecycle Stage:
  - Exit 71 (`sandbox_apply: Operation not permitted`) means the policy never became a usable compiled profile attached to the process at all; we failed in the “install compiled policy” stage.
  - Exit 1 with `EPERM` from `cat`/`sh` means the compiled PolicyGraph was installed and reached a deny Decision node for the probed Operation.
  - Exit -6 / SIGABRT with a crash report means the compiled policy did attach, but the combination of SBPL Profile and State starved some ambient requirement (dyld or similar) so badly that the process was terminated outside the “clean allow/deny” path.

- **Compiled Profile Source.**  
  The profiles under `book/evidence/experiments/op-table-operation/sb/` are harness SBPL Profiles, not App Sandbox templates or platform policies. In Compiled Profile Source terms, they are “test fixtures,” intended to exercise specific Operation and Filter combinations that the decoder grouped into bucket-4 and bucket-5. The runtime-checks harness is deliberately not using system `.sb` bundles yet; it isolates the experiment to these synthetic sources.

### 2. Operations, filters, and what is actually being probed

- **Operation focus.**  
  All of the probes are about two Operations: `file-read*` and `file-write*`. The bucket-4 SBPL Profile (`v1_read`) uses `(allow file-read*)` with no Filters, so the Operation is unconstrained by path in policy space even though the underlying OS may still deny writes or other actions for non-sandbox reasons. The bucket-5 SBPL Profile (`v11_read_subpath`) uses `(allow file-read* (subpath "/tmp/foo"))`, adding a `subpath` Filter that narrows the allow to a specific region of the filesystem.

- **Filter semantics vs expectations.**  
  The expected matrix in `out/expected_matrix.json` encodes a concept-level view: “bucket-4 = allow reads everywhere, writes nowhere; bucket-5 = allow reads only under `/tmp/foo`, deny reads elsewhere, deny writes.” That is a clean Operation × Filter × Decision story. The crashy behaviour for bucket-5 shows that in a real State, the SBPL Profile’s default `(deny default)` plus a single subpath Filter interacts with unmodeled dependencies (dyld, runtime, platform policies). The shims we added (`process-exec`, system path reads, tmp metadata) can be read as an implicit Filter vocabulary extension: we are manually adding the “hidden” Filters that the loader needs to function.

### 3. Buckets, PolicyGraph shape, and what the decoder expects

- **Bucket-level behaviour as PolicyGraph signature.**  
  Elsewhere in the repo, bucket-4 vs bucket-5 is a decoder-level clustering of PolicyGraph structure: a profile whose `file-read*` graph has no path Filter lands in bucket-4; a profile whose `file-read*` graph tests a `subpath` and then decides lands in bucket-5. The runtime-checks experiment is the runtime side of that story: can we observe, via probes, that the effective Decision for those Operations matches the bucket assignment?

- **Shim impact on graph structure.**  
  Every shim line we added is a new SBPL rule and therefore a new branch or node structure in the PolicyGraph:
  - `(allow process-exec*)` introduces a separate Operation entry for `process-exec*` with a trivial allow path; without it, the operation pointer table entry for `process-exec*` effectively points at a deny decision.
  - The global system path allows ( `/System`, `/usr`, `/bin`, `/sbin`, `/dev`, metadata on `/tmp`) likely add filter nodes to several file-related Operations, giving dyld and the runtime a path through the graph to allow their own `file-read*` operations.
  - The bucket-5-specific `(allow default)` followed by denies for `/tmp/bar` and `/tmp/foo` writes creates a PolicyGraph where `file-read*` and `file-write*` are still constrained on the specific probes, but many other operations now flow directly to an allow Decision. That is why the harness becomes stable but the profile is no longer “pure bucket-5” in a global sense.

### 4. Failure modes as different layers of the system

Using Orientation’s “stack and graph” mental model, the three failure modes we saw naturally align with different layers:

- **Harness-layer failure (exit 71).**  
  Here, the custom SBPL Profile and the State’s platform policies combine to deny `process-exec*` for the probe binaries themselves. The platform layer is fine; our harness SBPL Profile is too restrictive. No PolicyGraph for `file-read*` or `file-write*` is ever actually evaluated for the target process because we never get a running process under the sandbox.

- **Policy Decision-layer behaviour (exit 1, `EPERM`).**  
  Once process-exec and loader dependencies are unblocked, the denies we care about—`/etc/hosts` write for bucket-4, `/tmp/bar` read and `/tmp/foo` write for bucket-5—show up as clean “deny Decision reached in the relevant PolicyGraph” semantics. From Concepts’ point of view, these are the only outcomes that really validate or falsify our understanding of Operation, Filter, Decision, and PolicyGraph shape.

- **Environment/State-layer aborts (exit -6 / SIGABRT).**  
  The crash reports sit closer to Environment and State: the combination of SIP, hardened runtime, dyld shared cache layout, and our SBPL Profile left the process in a situation where Seatbelt (or another MAC/policy) terminates it. This is not the “deny with EPERM at a single Operation” story that the runtime-checks plan wanted; it is an example of how State2025 (Sonoma) constrains the use of sandbox-exec in ways that older Appendix-era examples did not.

### 5. Profile layers and what we are (not) modeling

- **Single layer vs real Policy Stack.**  
  In real processes, Policy Stack Evaluation Order combines platform, App Sandbox, and other layers. The runtime-checks harness intentionally ignores that complexity and installs a single test SBPL Profile via sandbox-exec. The loader failures and crashes are reminders that even in this toy setup, other platform layers (SIP, hardened runtime, dyld expectations) are still present and can dominate behaviour.

- **Teaching implication.**  
  For readers learning Seatbelt from this repo, this incident is a concrete illustration that:
  - A “minimal” SBPL Profile that looks correct at the SBPL and PolicyGraph level can still be unusable on a modern State because it conflicts with Environment-level invariants.
  - Runtime experiments must be designed with those invariants in mind; sometimes the harness needs its own small profile layer (our shims) that keeps the system viable while still letting you carve out a narrow region of the operation/filter space to study.

## Status

- Status: **partial / usable with caveats**.
- On this host:
  - `sandbox-exec` is functional with permissive profiles.
  - bucket-4 runs as intended with a small shim that allows `process-exec*` and basic loader paths.
  - bucket-5 requires a profile that uses `(allow default)` plus targeted denies, rather than a pure `(deny default)` subpath profile, to avoid SIGABRT.
- The harness now produces the expected runtime results for the probed operations, but:
  - the shimmed bucket-5 profile does not globally match the strict SBPL shape,
  - the exact crash mechanism under a strict `(deny default)` remains unresolved and is plausibly due to loader/resource starvation.

## Narrative summary

Started with pure SBPL profiles and a simple `sandbox-exec` harness; everything died with exit 71 because Seatbelt blocked `process-exec` for `cat`/`sh`. Verified `sandbox-exec` works when permissive. Added a `process-exec*` shim and absolute paths; bucket-4 recovered, but bucket-5 kept aborting (exit -6/SIGABRT). Layered in system file-read and tmp metadata allows; still crashed. Finally, for the bucket-5 subpath profile, flipped to `(allow default)` with targeted denies for `/tmp/bar` reads and `/tmp/foo` writes. That avoided the abort and produced the expected verdicts on the probed operations. Tradeoff: the runtime shim now diverges from the strict `(deny default)` policy, so unprobed operations may be over-permitted. Crash root cause under the strict profile remains unsolved; system profiles remain untested pending SBPL paths and a more robust, in-process probe.
