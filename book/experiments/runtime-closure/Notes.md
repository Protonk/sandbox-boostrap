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
- Preflight scan (v2 file + user-client IOKit): `v2_alias_literals.sb`, `v2_private_literals.sb`, `v2_data_literals.sb`, `v2_iokit_user_client_only.sb`, `v3_iokit_connection_user_client.sb` all `no_known_apply_gate_signature`.
- File spelling matrix run: `out/ea704c9c-5102-473a-b942-e24af4136cc8/` (launchd_clean, v2 file profiles).
  - Alias profile (`v2_alias_literals`) denies all six probes (`/etc`, `/private`, `/System/Volumes/Data` × `/etc/hosts` + `/tmp/foo`) at operation stage.
  - Private profile (`v2_private_literals`) allows `/private/etc/hosts`, `/System/Volumes/Data/private/etc/hosts`, `/private/tmp/foo`, `/System/Volumes/Data/private/tmp/foo`, and `/tmp/foo`; `/etc/hosts` remains denied.
  - Data profile (`v2_data_literals`) denies all six probes, including the Data spellings, at operation stage.
  - `path_witnesses.json` shows baseline `/etc/hosts` -> `/private/etc/hosts` and `/tmp/foo` -> `/private/tmp/foo`; scenario successes report `F_GETPATH_NOFIRMLINK` with `/System/Volumes/Data/private/...` for the private profile.
- IOKit user-client matrix run: `out/6ecc929d-fec5-4206-a85c-e3e265c349a7/` (launchd_clean).
  - `v2_user_client_only` allows `IOSurfaceRoot` (`open_kr=0`) at operation stage.
  - `v3_connection_user_client` denies with `open_kr=-536870174` and `EPERM` at operation stage.
- Preflight scan (IOKit op-identity lane): `v4_iokit_open_user_client.sb` classified as `no_known_apply_gate_signature`.
- IOKit op-identity run: `out/08887f36-f87b-45ff-8e9e-6ee7eb9cb635/` (v2 user-client-only) and `out/33ff5a68-262a-4a8c-b427-c7cb923a3adc/` (v4 iokit-open).
  - Both profiles allow `IOSurfaceRoot` (`open_kr=0`) at operation stage.
  - Op identity remains ambiguous (both `iokit-open-user-client` and `iokit-open` allow for this probe).
- Preflight scan (IOKit op-identity tri-matrix): `v5_iokit_service_only.sb`, `v6_iokit_user_client_only.sb`, `v7_iokit_service_user_client_both.sb` all `no_known_apply_gate_signature`.
- IOKit op-identity tri-matrix run `out/1034a7bd-81e1-41a1-9897-35f5556800c7/` failed in apply stage for v5/v6 because `with report` is invalid on deny rules; removed the report modifier and reran.
- IOKit op-identity tri-matrix run `out/fae371c2-f2f5-470f-b672-cf0c3e24d6c0/` (launchd_clean).
  - `v5_service_only`: `open_kr=-536870174` (EPERM), call not attempted; failure at operation stage.
  - `v6_user_client_only`: `open_kr=-536870174` (EPERM), call not attempted; failure at operation stage.
  - `v7_service_user_client_both`: `open_kr=0` and `call_kr=-536870206`; failure at operation stage.
  - Unsandboxed `book/api/runtime/native/probes/iokit_probe IOSurfaceRoot` returns `open_kr=0` with `call_kr=-536870206`, so the post-open call fails even without a sandbox.
- Emitted promotion packet for the file matrix run and refreshed VFS canonicalization mapping via `book/graph/mappings/vfs_canonicalization/generate_path_canonicalization_map.py` after updating `packet_set.json`.
