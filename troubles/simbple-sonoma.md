# simbple Sonoma extraction (partial)

## Context
- Host baseline: `book/world/sonoma-14.4.1-23E224-arm64/world.json` (Apple Silicon, SIP enabled).
- Tool: `book/tools/sbpl/simbple` (build via `book/tools/sbpl/simbple/build`).
- Goal: evaluate a Sonoma system SBPL profile using container metadata.
- Container metadata input: `~/Library/Containers/com.apple.AppStore/.com.apple.containermanagerd.metadata.plist`.

## Symptom
- Initial runs crashed during `load-profile` (Signal 11/6) with unbound variables for new Sonoma ops/filters/modifiers and SBPL constructs (e.g., `system-fcntl`, `system-mac-syscall`, `mac-policy-name`, `telemetry`).
- Additional failures were triggered by imported profiles carrying `(version 3)` when the base profile uses `(version 1)`.
- Missing named arguments for `fcntl-command` and `fsctl-command` surfaced as unbound variables.
- Current behavior (v1-only enforcement): `simbple` exits early with an explicit error when a profile or snippet declares `(version 2/3)`, rather than segfaulting.

## Reproduction
```sh
SIMBPLE_TRACE=1 ./bin/simbple --platforms=catalina \
  -o /tmp/simbple-out.sb \
  ~/Library/Containers/com.apple.AppStore/.com.apple.containermanagerd.metadata.plist
```
After enforcing SBPL v1-only semantics in `book/tools/sbpl/simbple/src/scm/sbpl.scm`, the same command now crashes during `load-profile` (Signal 11) with trace output stopping at:
```
[trace] load-profile
```
After adding explicit version preflight checks, the same command now exits with a clear error:
```
[trace] sbpl-version path=/System/Library/Sandbox/Profiles/system.sb
[trace] sbpl-version result=3
[Err]: unsupported SBPL version 3 in /System/Library/Sandbox/Profiles/system.sb (only version 1 is allowed)
```

Additional container metadata inputs tested without permissive mode:
```sh
SIMBPLE_TRACE=1 ./bin/simbple --platforms=catalina -o /tmp/simbple-archiveutility.sb \
  ~/Library/Containers/com.apple.archiveutility/.com.apple.containermanagerd.metadata.plist
SIMBPLE_TRACE=1 ./bin/simbple --platforms=catalina -o /tmp/simbple-facetime.sb \
  ~/Library/Containers/com.apple.FaceTime/.com.apple.containermanagerd.metadata.plist
SIMBPLE_TRACE=1 ./bin/simbple --platforms=catalina -o /tmp/simbple-ibooks.sb \
  ~/Library/Containers/com.apple.iBooks.BooksThumbnail/.com.apple.containermanagerd.metadata.plist
```
All three crash in the same place (`load-profile`, Signal 11).

## Interpretation
- Partial: the Catalina platform data and SBPL shim needed Sonoma-specific additions (new operations/filters/modifiers, version handling, and missing named args). With SBPL v1-only enforcement, the tool now fails fast when encountering `(version 3)` in imported system profiles; that is correct per the rule but blocks real-world system profiles on this host.
- Partial: to avoid segfaults on unsupported versions, a C-side abort path (`%sbpl-unsupported-version`) now exits the process immediately after printing the version error. This is a pragmatic guardrail, not a validated SBPL behavior.
- Partial: libsandbox string tables on this host provide values for `*ios-sandbox-system-container*`, `*ios-sandbox-system-group*`, and `*sandbox-executable-bundle*`, which have been applied. No string evidence yet for `*ios-sandbox-executable*`.

## Status
- blocked — enforcing SBPL v1-only semantics now exits cleanly on `(version 3)` in imported profiles (e.g., `system.sb`, `contacts.sb`), so extraction cannot proceed for the default system profile set on this host.

## Current Blockers
- `application.sb` imports `system.sb`, which declares `(version 3)` and triggers the v1-only abort path immediately; this is a hard stop for the default container metadata flow.
- The snippet list includes `contacts.sb` (also `(version 3)`), which would also fail under strict v1-only enforcement even if `system.sb` were bypassed.
- `*ios-sandbox-executable*` remains a placeholder; no host string evidence found yet (hypothesis).
- Extraction has only been validated with the v2/v3 compatibility shim; under v1-only semantics, baseline container metadata inputs fail early before any rule output is produced.

## Pointers
- SBPL shim changes: `book/tools/sbpl/simbple/src/scm/sbpl.scm`, `book/tools/sbpl/simbple/src/scm/sbpl_v1.scm`.
- Version checks and aborts: `book/tools/sbpl/simbple/src/misc/scheme_support.c`, `book/tools/sbpl/simbple/src/misc/scheme_support.h`, `book/tools/sbpl/simbple/src/sb/evaluate.c`.
- Platform data expansions: `book/tools/sbpl/simbple/src/platform_data/catalina/operations.c`, `book/tools/sbpl/simbple/src/platform_data/catalina/filters.c`.
- Modifier extensions: `book/tools/sbpl/simbple/src/sb/modifiers.c`.
- Trace/output examples: `/tmp/simbple-trace.log`, `/tmp/simbple-out.sb`.

## Artifact Evidence (partial)
- `book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib` string tables include:
  - `*ios-sandbox-system-container*` → `com.apple.sandbox.system-container`
  - `*ios-sandbox-system-group*` → `com.apple.sandbox.system-group`
  - `*sandbox-executable-bundle*` → `com.apple.sandbox.executable`
- No string evidence yet for `*ios-sandbox-executable*` in libsandbox (hypothesis).
- Host system profiles: `/System/Library/Sandbox/Profiles/system.sb` and `/System/Library/Sandbox/Profiles/contacts.sb` both declare `(version 3)` on this host baseline.

## Log (append-only)
- 2024-12-03: extracted `fcntl-command` and `fsctl-command` named-argument values from `book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib` (world_id `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`) and replaced placeholders in `book/tools/sbpl/simbple/src/platform_data/catalina/filters.c` (`F_GETCONFINED`, `F_SETCONFINED`, and `APFSIOC_*` values).
- 2024-12-03: confirmed libsandbox contains `*ios-sandbox-container*` and `*ios-sandbox-application-group*` strings but no concrete values for `*ios-sandbox-system-container*`, `*ios-sandbox-system-group*`, or `*ios-sandbox-executable*`.
- 2024-12-03: removed the ad-hoc `iokit-user-client-class` filter entry from `book/tools/sbpl/simbple/src/platform_data/catalina/filters.c` to align with `book/graph/mappings/vocab/filters.json` (SBPL aliases it to `iokit-registry-entry-class`).
- 2024-12-03: rebuilt `simbple` and verified extraction succeeds without `SIMBPLE_PERMISSIVE=1` for `~/Library/Containers/com.apple.AppStore/.com.apple.containermanagerd.metadata.plist` (initial run hit a 10s timeout; rerun with a larger timeout completed).
- 2024-12-03: updated `book/tools/sbpl/simbple/src/scm/sbpl.scm` to enforce SBPL v1-only semantics; any `version` other than 1 now triggers an error.
- 2024-12-03: reran `simbple` without permissive mode against AppStore, Archive Utility, FaceTime, and iBooks container metadata; all crash at `load-profile` with Signal 11 after the v1-only change (`/tmp/simbple-*.log` capture traces that stop at `load-profile`).
- 2024-12-03: attempted a diagnostic run with `SIMBPLE_SKIP_PROFILE=1` (AppStore metadata) to isolate snippet loading; encountered unbound variables (`entitlement`, `when*`, `home-subpath`) and an assertion failure in `sbpl_create_rule` (Signal 6).
- 2024-12-03: searched `book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib` for `*ios-sandbox-*` values; found `com.apple.sandbox.system-container`, `com.apple.sandbox.system-group`, and `com.apple.sandbox.executable` strings (partial host evidence) and updated `book/tools/sbpl/simbple/src/scm/sbpl_v1.scm` accordingly. No `*ios-sandbox-executable*` string found.
- 2024-12-03: added a profile preflight that scans `(version N)` directives in `book/tools/sbpl/simbple/src/misc/scheme_support.c` and a `%sbpl-version` foreign function to expose the check to Scheme; `load` now rejects any version other than 1.
- 2024-12-03: added `%sbpl-unsupported-version` to emit a fatal error and `exit(EXIT_FAILURE)` when a non-v1 profile is encountered; this avoids the earlier segfault path at the cost of a hard process exit.
- 2024-12-03: verified that `system.sb` (version 3) now fails fast with a clear error instead of a segfault when loaded directly or via `load`.
- 2024-12-03: re-ran the default AppStore container extraction; it now exits early with an explicit unsupported version error from `system.sb` rather than crashing.
- Added socket constants (`AF_INET=2`, `AF_SYSTEM=32`, `SOCK_STREAM=1`, `SOCK_DGRAM=2`, `IPPROTO_TCP=6`, `IPPROTO_UDP=17`) to `book/tools/sbpl/simbple/src/scm/sbpl_v1.scm` using the libsandbox-encoder network-matrix witness (`book/experiments/field2-final-final/libsandbox-encoder/Notes.md`, partial) and rebuilt `simbple`; network-matrix v1 profiles now load under `SIMBPLE_PERMISSIVE=1` and `SIMBPLE_SKIP_SNIPPETS=1`.
- Added `iokit-async-external-method`, `iokit-external-method`, and `iokit-external-trap` to `book/tools/sbpl/simbple/src/platform_data/catalina/operations.c` (mapped to `iokit*`) and introduced an `apply-message-filter` placeholder (`book/tools/sbpl/simbple/src/scm/sbpl_v1.scm` macro → `(with "apply-message-filter")`, `book/tools/sbpl/simbple/src/sb/modifiers.c` modifier); nested message-filter rules are ignored (partial) but the v1 gate-witness minimal profile now loads cleanly.
- Re-ran the v1 corpus (`book/tools/sbpl/corpus`) with `SIMBPLE_PERMISSIVE=1` + `SIMBPLE_SKIP_SNIPPETS=1`; all v1 entries now exit cleanly.
- Decision: keep the `apply-message-filter` placeholder path (flat modifier, ignore nested rules) because the early substrate sources describe modifiers as a flat list and do not mention message-filter nesting; this is a hypothesis inference with no host witness yet.
