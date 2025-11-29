# Profile Blobs – Current State and Blockers

## Problem
We need to apply compiled sandbox profile blobs (`.sb.bin`, e.g., system profiles `airlock.sb.bin`, `bsd.sb.bin`) at runtime. SBPL-mode wrapper works; blob-mode is still missing because we cannot locate or resolve the private apply API (`sandbox_apply` / similar) on this host.

## What we tried
1. **Library discovery**
   - Searched for `libsandbox.dylib` / `libsystem_sandbox.dylib` under `/usr/lib`, `/System/Library/PrivateFrameworks`, `/System/Library/Frameworks`, `/System/Library/PrivateFrameworks/AppSandbox.framework`. Nothing readable/found via `nm` or `find` (paths either absent or permission-blocked).
   - Attempted to `nm` the dyld cache (`/System/Library/dyld/dyld_shared_cache_arm64`); cache not found on this host (likely trimmed or different path).
   - `otool`/`strings` attempts on candidate libsystem files failed (files not present).

2. **Existing wrappers**
   - SBPL wrapper (`book/api/SBPL-wrapper/wrapper`) works for SBPL text via `sandbox_init`.
   - Runtime harness (`sandbox_runner`/`sandbox_reader`) works for SBPL profiles (including metafilter) when applying via `sandbox_init`.
   - Blob apply remains the missing piece.

3. **Known artifacts**
   - Compiled system blobs live at `book/examples/extract_sbs/build/profiles/airlock.sb.bin` and `bsd.sb.bin`.
   - Digests exist in `book/graph/mappings/system_profiles/digests.json` (operation counts, op-table buckets).
   - Vocab/tag mappings exist in `book/graph/mappings/vocab/` and `.../tag_layouts/`.

## Hypothesis
The host environment hides `libsandbox` inside the dyld cache and we don’t have a path to it. Without symbol access, we can’t dlsym `sandbox_apply` (or equivalent) to build blob mode. A SBPL disassembly fallback is possible via `sbdis`, but blob-apply remains preferable for fidelity.

## Next actions (blocked until symbols found)
1. Locate `libsandbox` / `libsystem_sandbox` or the dyld cache slice containing sandbox APIs.
2. Identify the private apply symbol and struct signature (likely `sandbox_profile_t { profile_type, reserved, bytecode, bytecode_length }`).
3. Build a minimal blob-apply probe to confirm we can apply a tiny blob (e.g., allow_all.sb.bin).
4. Wire blob mode into the wrapper once the apply API is known.

## Fallback
If blob mode remains unavailable, disassemble system blobs to SBPL (`sbdis`) and use the SBPL wrapper (accepting lossy conversion) for runtime probes.

## Update (2026-XX-XX)
- Found dyld caches under `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` (including `dyld_shared_cache_arm64e` and map files). No extractor installed; `extract_cache.sh` stub added in `book/api/SBPL-wrapper` but fails until `dyld-shared-cache-extractor` (or equivalent) is available.
- System SBPL text profiles are present on disk under `/System/Library/Sandbox/Profiles/` (e.g., `airlock.sb`, `bsd.sb`), so SBPL fallback is viable without decompiling blobs.
- Blob mode remains blocked pending cache extraction and symbol inspection for `sandbox_apply`/`sandbox_apply_container`.

## Update (cache extracted externally)
- `libsystem_sandbox.dylib` is available under `book/graph/mappings/dyld-libs/usr/lib/system/libsystem_sandbox.dylib` (extracted from the cache). `nm` shows sandbox-related symbols (`sandbox_check*`, `sandbox_register_app_bundle_*`, etc.) but no `sandbox_apply`/`sandbox_apply_container` exports in the global symbol table.
- Next: inspect the extracted dylib for private symbols (internal, non-exported) or consider that blob-apply may be non-exported on this build; SBPL fallback remains viable.

## Update (libsandbox.1 extracted)
- Extracted `libsandbox.1.dylib` from the cache using `dyld-shared-cache-extractor` (cache path `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e`); placed at `book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib`.
- `nm -gU libsandbox.1.dylib` shows `sandbox_apply`, `sandbox_apply_container`, `sandbox_compile_*`, `sandbox_create_params/set_param/free_params/free_profile` exported. Blob-mode wiring can target this dylib directly.

## Blob mode integration attempt (runtime harness)
- Wired runtime harness to use compiled blobs for `sys:airlock`/`sys:bsd` via the wrapper’s `--blob` path. Probes now fail with `sandbox initialization failed: no version specified` when applying `.sb.bin` blobs via `sandbox_runner`/`sandbox_reader`. This indicates the blob mode is still going through SBPL init rather than `sandbox_apply`, or the wrapper is not invoked for these probes.
- Next steps: ensure `run_probes.py` actually invokes the blob-aware wrapper for blob-mode entries, and that `sandbox_apply` is called instead of `sandbox_init`. If issues persist, check whether the compiled blobs need a version header or different apply flags.
