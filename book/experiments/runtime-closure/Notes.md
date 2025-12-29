# Runtime Closure – Notes

Use this file for short, factual run notes and failures. Avoid timestamps.

- Preflight scan (file lane): `v1_etc_alias_only.sb`, `v1_etc_private_only.sb`, `v1_etc_both.sb` all classified as `no_known_apply_gate_signature`.
- File lane runtime run: `out/5a8908d8-d626-4cac-8bdd-0f53c02af8fe/` (launchd_clean, file-only profiles).
  - `/etc/hosts` denied under all three profiles (including the both-paths profile).
  - `/private/etc/hosts` allowed under private-only and both; denied under alias-only.
  - `/tmp/foo` denied under all three profiles.
  - `path_witnesses.json` baseline shows `/etc/hosts` -> `/private/etc/hosts` and `/tmp/foo` -> `/private/tmp/foo`; scenario allows show `F_GETPATH_NOFIRMLINK:/System/Volumes/Data/private/etc/hosts` on success.
- Preflight scan (mach lane): `v1_mach_service_discriminator.sb` classified as `no_known_apply_gate_signature`.
- Mach lane runtime run: `out/66315539-a0ce-44bf-bff0-07a79f205fea/` (launchd_clean, mach-only profile).
  - `com.apple.cfprefsd.agent` allowed in baseline and scenario (`kr=0`).
  - `com.apple.sandbox-lore.missing` returns `kr=1102` in baseline and scenario (missing service, not a sandbox denial).
- Baseline IOKit probe sweep picked `IOSurfaceRoot` as a present class with `open_kr=0`.
- Preflight scan (IOKit lane): `v1_iokit_class_only.sb` classified as `no_known_apply_gate_signature`.
- IOKit lane runtime run: `out/48086066-bfa2-44bb-877c-62dd1dceca09/` (launchd_clean, IOKit-only profile).
  - Baseline `iokit_probe` for `IOSurfaceRoot` returns `found=true` and `open_kr=0`.
  - Scenario `sandbox_iokit_probe` returns `found=true` with `open_kr=-536870174` and `EPERM` (deny at probe stage).
