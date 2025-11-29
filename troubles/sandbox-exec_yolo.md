# Seatbelt runtime harness – sandbox-exec path (State: macOS 14.4.1 / SIP on)

This is a detailed read-out of the sandbox-exec harness work in `book/experiments/runtime-checks/`, keeping to the substrate’s State/Concept vocabulary. Sequence first, narrative summary appended at the end.

## Context
- Host State: macOS 14.4.1 (23E224), Apple Silicon, SIP enabled.
- Goal: run the bucket-4 (`v1_read`) and bucket-5 (`v11_read_subpath`) SBPL profiles via sandbox-exec to collect runtime allow/deny traces for the runtime-checks experiment.
- Harness: `run_probes.py` driving sandbox-exec with SBPL source (not the compiled `.sb.bin`), writing `out/runtime_results.json`.

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

## Narrative summary (appended)
Started with pure SBPL profiles and a simple sandbox-exec harness; everything died with exit 71 because Seatbelt blocked `process-exec` for `cat`/`sh`. Verified sandbox-exec works when permissive. Added process-exec shim and absolute paths; bucket-4 recovered, but bucket-5 kept aborting (exit -6/SIGABRT). Layered in system file-read and tmp metadata allows; still crashed. Finally, for the bucket-5 subpath profile, flipped to `(allow default)` with targeted denies for `/tmp/bar` reads and `/tmp/foo` writes. That avoided the abort and produced the expected verdicts on the probed operations. Tradeoff: the runtime shim now diverges from the strict `(deny default)` policy, so unprobed operations may be over-permitted. Crash root cause under the strict profile remains unsolved; no sandboxd telemetry was visible, only crash reports pointing at Seatbelt/dyld resource issues. System profiles remain untested pending SBPL paths.
