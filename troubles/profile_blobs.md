# Profile blobs – current state and blockers

## Problem

We need to apply compiled sandbox profile blobs (`.sb.bin`), including system profiles such as `airlock.sb.bin` and `bsd.sb.bin`, at runtime. The SBPL-mode wrapper works, and we can now call the private apply API (`sandbox_apply` / `sandbox_apply_container`) via `libsandbox.1.dylib`, but blob mode still behaves differently for platform profiles: custom blobs apply cleanly, while some shipped platform blobs fail with `EPERM`.

## What we tried
1. **Library discovery**
   - Searched for `libsandbox.dylib` / `libsystem_sandbox.dylib` under `/usr/lib`, `/System/Library/PrivateFrameworks`, `/System/Library/Frameworks`, `/System/Library/PrivateFrameworks/AppSandbox.framework`. Nothing readable/found via `nm` or `find` (paths either absent or permission-blocked).
   - Attempted to `nm` the dyld cache (`/System/Library/dyld/dyld_shared_cache_arm64`); cache not found on this host (likely trimmed or different path).
   - `otool`/`strings` attempts on candidate libsystem files failed (files not present).

2. **Existing wrappers**
   - SBPL wrapper (`book/tools/sbpl/wrapper/wrapper`) works for SBPL text via `sandbox_init`.
   - Runtime harness (`sandbox_runner`/`sandbox_reader`) works for SBPL profiles (including metafilter) when applying via `sandbox_init`.
   - Blob apply remains the missing piece.

3. **Known artifacts**
   - Compiled system blobs live at `book/evidence/graph/concepts/validation/fixtures/blobs/airlock.sb.bin` and `bsd.sb.bin`.
   - Digests exist in `book/evidence/graph/mappings/system_profiles/digests.json` (operation counts, op-table buckets).
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

## Update
- Found dyld caches under `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` (including `dyld_shared_cache_arm64e` and map files). No extractor installed; `extract_cache.sh` stub added in `book/tools/sbpl/wrapper` but fails until `dyld-shared-cache-extractor` (or equivalent) is available.
- System SBPL text profiles are present on disk under `/System/Library/Sandbox/Profiles/` (e.g., `airlock.sb`, `bsd.sb`), so SBPL fallback is viable without decompiling blobs.
- Blob mode remains blocked pending cache extraction and symbol inspection for `sandbox_apply`/`sandbox_apply_container`.

## Update: cache extracted externally
- `libsystem_sandbox.dylib` is available under `book/evidence/graph/mappings/dyld-libs/usr/lib/system/libsystem_sandbox.dylib` (extracted from the cache). `nm` shows sandbox-related symbols (`sandbox_check*`, `sandbox_register_app_bundle_*`, etc.) but no `sandbox_apply`/`sandbox_apply_container` exports in the global symbol table.
- Next: inspect the extracted dylib for private symbols (internal, non-exported) or consider that blob-apply may be non-exported on this build; SBPL fallback remains viable.

## Update: libsandbox.1 extracted
- Extracted `libsandbox.1.dylib` from the cache using `dyld-shared-cache-extractor` (cache path `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e`); placed at `book/evidence/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib`.
- `nm -gU libsandbox.1.dylib` shows `sandbox_apply`, `sandbox_apply_container`, `sandbox_compile_*`, `sandbox_create_params/set_param/free_params/free_profile` exported. Blob-mode wiring can target this dylib directly.

## Blob mode integration attempt (runtime harness)
- Wired runtime harness to use compiled blobs for `sys:airlock`/`sys:bsd` via the wrapper’s `--blob` path. Probes now fail with `sandbox initialization failed: no version specified` when applying `.sb.bin` blobs via `sandbox_runner`/`sandbox_reader`. This indicates the blob mode is still going through SBPL init rather than `sandbox_apply`, or the wrapper is not invoked for these probes.
- Next steps: ensure `run_probes.py` actually invokes the blob-aware wrapper for blob-mode entries, and that `sandbox_apply` is called instead of `sandbox_init`. If issues persist, check whether the compiled blobs need a version header or different apply flags.

## Update: EPERM on platform blobs

- After wiring `run_probes.py` to route blob-mode profiles through `book/tools/sbpl/wrapper/wrapper --blob`, system blobs (`airlock.sb.bin`, `bsd.sb.bin`) now fail at apply with `sandbox_apply: Operation not permitted` before exec. Custom blobs (e.g., `allow_all.sb.bin`) apply cleanly.
- Likely cause: these are platform profile layers that the kernel only installs when handed down by secinit/sandboxd with platform credentials; ad hoc `sandbox_apply` from an unsigned/non-platform process is rejected.
- Workarounds: use SBPL text imports for system profiles, or run blob apply on a permissive/entitled host. Pending: inspect blob headers/flags to confirm platform-only provenance.

## Header inspection (decoder)

- Ran `book.api.profile.decoder.decode_profile` on `airlock.sb.bin`, `bsd.sb.bin`, and a custom `allow_all.sb.bin`.
- Preamble words (16-bit LE): `airlock=[16384,167,190,0,0,1,7,283]`, `bsd=[0,28,190,0,0,0,0,27]`, `allow_all=[0,2,190,0,0,0,0,1]`. Word0 differs: `airlock` carries `0x4000`, others `0x0000`. Word1 aligns with op_count (167/28/2).
- Early 32-byte hex (LE pairs): `airlock` starts `0040 a700 be00 ...`, `bsd` starts `0000 1c00 be00 ...`, `allow_all` starts `0000 0200 be00 ...`. No explicit type field surfaced by the current decoder, but the `0x4000` word0 on `airlock` may mark platform provenance.
- Sections: decoder still slices op-table at byte 16 for `op_count*2`; nodes/literal offsets differ due to size, not flags.
- No discriminating “profile type” field is exposed yet; next step is to expose more header words/flags in the decoder or compare against known format docs.

### Header dump via CLI helper

- Using `python -m book.api.profile decode dump --summary`, outputs for key blobs:
  - `airlock.sb.bin`: `op_count=167`, `maybe_flags=16384 (0x4000)`, `word0=16384`, `word2=190`, heuristic `profile_class=0` at word index 3.
  - `bsd.sb.bin`: `op_count=28`, `maybe_flags=0`, `word0=0`, `word2=190`, heuristic `profile_class=0` at word index 0.
  - `allow_all.sb.bin` (custom): `op_count=2`, `maybe_flags=0`, `word0=0`, `word2=190`, heuristic `profile_class=0` at word index 0.
- Full header (64-byte) dumps show `header_fields.magic=0x00be` across all, word1=op_count, and `unknown_words` populated with trailing header words. Heuristic `profile_class` is 0 for all three; `maybe_flags=0x4000` still only on `airlock`. Platform-only provenance likely enforced via caller credentials and/or deeper class fields not yet decoded.

## Recompiled SBPL apply attempts (this host)
- Recompiled SBPL text from `/System/Library/Sandbox/Profiles/{airlock,bsd}.sb` using `sandbox_compile_string` and applied via `sandbox_apply`:
  - `bsd` compiled blob applies successfully (`rc=0`).
  - `airlock` compiled blob still fails (`rc=-1`, errno EPERM).
- `sandbox_init` on SBPL text:
  - `bsd` SBPL applies cleanly (`rc=0`).
  - `airlock` SBPL fails with `Operation not permitted` on this host.
- Direct `wrapper --blob` on shipped blobs:
  - `airlock` fails `sandbox_apply: Operation not permitted`.
  - `bsd` path failed earlier due to execvp permission when invoking the wrapped command; need a simpler noop exec to confirm apply status, but SBPL compiled/apply suggests base blob may be acceptable if exec hurdles are cleared.

## Status

- Status: **partial**.
- On this host:
  - blob-mode apply works for custom and recompiled SBPL profiles (e.g., `allow_all.sb.bin`, compiled `bsd`),
  - shipped `airlock` profile remains gated by `EPERM` under both SBPL and blob apply.
- Impact:
  - runtime probes that need to observe the exact platform `airlock` policy via blob mode remain blocked,
  - SBPL text imports are available as a fallback for most system profiles, with the caveat that compiler behavior may differ from the shipped blobs.
- Further work should:
  - clarify whether the `EPERM` gate is purely caller-credential based or tied to header flags like `maybe_flags=0x4000`,
  - and document any additional provenance checks in the experiments that rely on platform blobs.
