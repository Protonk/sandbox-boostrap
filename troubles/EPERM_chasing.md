# EPERM when applying system blobs (`airlock.sb.bin`, `bsd.sb.bin`)

## Context

- Host: Sonoma baseline (see `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)`).
- Surface: applying compiled system sandbox blobs (`airlock.sb.bin`, `bsd.sb.bin`) via `sandbox_apply` in `book/tools/sbpl/wrapper/wrapper --blob`, under the `runtime-checks` harness.
- Profiles: shipped blobs from `book/examples/extract_sbs/build/profiles/` (extracted from `/System/Library/Sandbox/Profiles/*.sb.bin` via the `extract_sbs` helper).

## Symptom

- `sandbox_apply` returns `EPERM` when applying system blobs (notably `airlock`); custom blobs such as `allow_all.sb.bin` apply cleanly.
- SBPL-mode profiles applied via `sandbox_init` work for synthetic/custom SBPL; system SBPL imports routed through blob mode hit the same gate.

## Interpretation

- Substrate framing:
  - Orientation/Concepts treat platform profiles such as `airlock` and `bsd` as platform-layer policies attached by secinit/sandboxd with platform credentials.
  - Policy Stack Evaluation Order assumes these are installed as part of the platform label, not ad hoc by unprivileged callers.
- On this host, the EPERM appears as a platform-only gate:
  - apply failures occur before any PolicyGraph evaluation,
  - header inspection shows `airlock` carries `maybe_flags=0x4000` and `op_count=167`, while `bsd` and `allow_all` carry `maybe_flags=0x0000` and smaller op-counts.
  - recompiled SBPL for `bsd` applies, but `airlock` still fails even when recompiled.

## Steps taken

- Wired `run_probes.py` to route blob-mode profiles through `book/tools/sbpl/wrapper/wrapper --blob`, so all blob applies go through the same path.
- Used `book.api.profile_tools.decoder` (with header exposure) to dump preamble words:
  - `airlock`: `maybe_flags=0x4000`, `op_count=167`, `magic=0x00be`.
  - `bsd`: `maybe_flags=0x0000`, `op_count=28`, `magic=0x00be`.
  - `allow_all` (custom): `maybe_flags=0x0000`, `op_count=2`, `magic=0x00be`.
- Tried SBPL fallback:
  - compiled system SBPL text from `/System/Library/Sandbox/Profiles/{airlock,bsd}.sb` via `sandbox_compile_string`,
  - applied compiled blobs via `sandbox_apply` and text via `sandbox_init`.
  - On this host:
    - `bsd` compiled blob and SBPL text both apply cleanly.
    - `airlock` compiled blob and SBPL text both fail with `EPERM`.

## Impact

- `runtime-checks` experiment:
  - system profiles `sys:airlock` and `sys:bsd` record apply-fail denies when using shipped blobs; runtime behavior for platform policies cannot be validated via blob mode on this host.
  - `bsd` can be exercised via SBPL/recompiled blob, but `airlock` remains blocked.
- `sbpl-graph-runtime`:
  - any planned blob-mode runtime triples for platform profiles are blocked by this gate.
- Blob-mode validation generally:
  - shipped platform blobs cannot be applied ad hoc from this process context; SBPL imports and recompiled blobs are the only viable path for runtime work.

## Status

- Status: **partial / expected gate**.
- On this Sonoma host:
  - blob-mode apply works as expected for custom and some system-derived blobs (`bsd` via SBPL),
  - `airlock` behaves as a platform-only profile that cannot be applied from a non-platform caller, regardless of whether the blob is shipped or recompiled.
- From the substrate lens:
  - this is consistent with a provenance/credential gate enforced by libsandbox and the kernel for platform-layer policies,
  - there is no evidence that flipping a simple header flag would make `airlock` applicable outside a platform context.
- Next steps (tracked in the relevant experiments, not here):
  - document this EPERM behavior in `runtime-checks` and `profile_blobs` as a structural limitation of this host,
  - continue to use SBPL text and recompiled blobs for system profiles where possible, and treat `airlock` as a “platform-only” case in runtime examples.
