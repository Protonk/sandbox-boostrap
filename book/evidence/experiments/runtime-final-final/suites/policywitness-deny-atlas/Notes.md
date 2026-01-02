# policywitness-deny-atlas (Notes)

- Initialized experiment scaffold.
- `smoke-0f3bee8f-2cbc-4339-a076-f1fc023094f9`: ran without elevation; probes failed with `xpc_error` (Sandbox restriction, error 159) and observer skipped (missing pid/process name).
- `smoke-8ecb378c-fd7f-443a-8575-b7faf951ed43`: `--capture-sandbox-logs` run; host capture failed with `missing child_pid for sandbox log capture`.
- `smoke-f0db6faf-1afb-429d-ba0d-720499effdbb`: manual observer (`--last 30s`); 27 records, 7 mapped denies. File operations mapped with `filter_inferred`; network-outbound mapped with explicit `remote` filter. Several permission-shaped failures had no deny evidence.
- `smoke-fd118439-a88a-44c6-954d-5c80afba9714`: manual observer with time-range + correlation id; only 6 mapped denies and minimal had none. Time-range window appears brittle.
- `smoke-dc03c1fb-270e-4a75-901c-6ecdfd557156`: manual observer (`--last 30s`) + correlation id; 27 records, 12 mapped denies across all three profiles. File operations mapped with `filter_inferred`; one explicit `remote` filter via `network-outbound`.
- Diff `smoke-f0db6faf-1afb-429d-ba0d-720499effdbb` vs `smoke-dc03c1fb-270e-4a75-901c-6ecdfd557156`: 7 row_ids flipped between hypothesis and mapped. `temporary_exception.net_op_tcp_connect_control` flipped from mapped → hypothesis; several `fs_op_listdir_home_*` rows flipped to mapped. Stability is not yet established.
- Attempted `--manual-observer-last 60s` run hit `NameError: probe_out` in `run_smoke.py` (manifest write). Fixed by using `run_root` for `probe_output_dir`.
- `smoke-71899407-fcef-4054-9fb8-6b3ed5276587`: manual `--last 60s` run; 10 row flips vs `smoke-dc03...` (unstable).
- `smoke-53266e96-e411-445e-bd39-691554845047` / `smoke-aac77a40-46e3-4114-83a2-07bf6d581ee2`: core probe set (no stateful probes) yields 0–1 mapped denies; deny yield too low.
- `smoke-6314b2b4-d2e7-43e1-8169-3861cd6c592d`: external observer (time-range) with core probe set yields 1 mapped deny.
- `smoke-df029550-1d70-4c8a-a810-2c212e803eb9` / `smoke-b0fb0aee-f1e1-4144-ab5a-ef69ffa658d1`: include-stateful probes + unique `downloads_rw` filename; 27 records with 7–8 mapped denies; only one row flip (`net_client.downloads_rw_probe`).
- `smoke-bd9d0f87-b3f0-4070-a934-75b2223f1870` / `smoke-162aeb4f-6e86-4ff7-a664-73f923e642e3`: external observer + include-stateful probes; 3 row flips and lower deny yield than manual.
- `smoke-2f1ae2be-9441-48e2-a9f8-e5bffb477a11`: capture mode; `host_sandbox_log_capture` still fails with `missing child_pid for sandbox log capture`.
- `smoke-2cbc3597-9aac-4abb-b188-e16cb244f4b3`: include-stateful + downloads ladder; 39 records, 21 mapped denies. Downloads ladder probes (fs_op create path-class/direct, fs_coordinated_op write, downloads_rw) all yielded observed deny lines; sandbox_check control did not.
- `smoke-233b9861-ae8a-45b1-be28-77a22e2297c7`: repeat of downloads ladder run; only flips were `minimal.fs_op_deny_private_overrides` and `minimal.net_op_tcp_connect_control`. Downloads ladder rows stayed mapped in both runs.
