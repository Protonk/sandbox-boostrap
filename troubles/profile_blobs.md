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

## Update (EPERM on platform blobs)

- After wiring `run_probes.py` to route blob-mode profiles through `book/api/SBPL-wrapper/wrapper --blob`, system blobs (`airlock.sb.bin`, `bsd.sb.bin`) now fail at apply with `sandbox_apply: Operation not permitted` before exec. Custom blobs (e.g., `allow_all.sb.bin`) apply cleanly.
- Likely cause: these are platform profile layers that the kernel only installs when handed down by secinit/sandboxd with platform credentials; ad hoc `sandbox_apply` from an unsigned/non-platform process is rejected.
- Workarounds: use SBPL text imports for system profiles, or run blob apply on a permissive/entitled host. Pending: inspect blob headers/flags to confirm platform-only provenance.

## Header inspection (decoder)

- Ran `book.api.decoder.decode_profile` on `airlock.sb.bin`, `bsd.sb.bin`, and a custom `allow_all.sb.bin`.
- Preamble words (16-bit LE): `airlock=[16384,167,190,0,0,1,7,283]`, `bsd=[0,28,190,0,0,0,0,27]`, `allow_all=[0,2,190,0,0,0,0,1]`. Word0 differs: `airlock` carries `0x4000`, others `0x0000`. Word1 aligns with op_count (167/28/2).
- Early 32-byte hex (LE pairs): `airlock` starts `0040 a700 be00 ...`, `bsd` starts `0000 1c00 be00 ...`, `allow_all` starts `0000 0200 be00 ...`. No explicit type field surfaced by the current decoder, but the `0x4000` word0 on `airlock` may mark platform provenance.
- Sections: decoder still slices op-table at byte 16 for `op_count*2`; nodes/literal offsets differ due to size, not flags.
- No discriminating “profile type” field is exposed yet; next step is to expose more header words/flags in the decoder or compare against known format docs.

### Header dump via CLI helper

- Using `python -m book.api.decoder dump --summary`, outputs for key blobs:
  - `airlock.sb.bin`: `op_count=167`, `maybe_flags=16384 (0x4000)`, `word0=16384`, `word2=190`.
  - `bsd.sb.bin`: `op_count=28`, `maybe_flags=0`, `word0=0`, `word2=190`.
  - `allow_all.sb.bin` (custom): `op_count=2`, `maybe_flags=0`, `word0=0`, `word2=190`.
- Full header (64-byte) dumps show `header_fields.magic=0x00be` across all, word1=op_count, and `unknown_words` populated with trailing header words. The only clear discriminator so far is `maybe_flags=0x4000` on `airlock`; `bsd` matches the custom blob on flags. Platform-only provenance may be flagged differently per profile; more analysis needed if EPERM persists on both.
