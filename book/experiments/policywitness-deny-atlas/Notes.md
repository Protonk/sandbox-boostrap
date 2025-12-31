# policywitness-deny-atlas (Notes)

- Initialized experiment scaffold.
- `smoke-0f3bee8f-2cbc-4339-a076-f1fc023094f9`: ran without elevation; probes failed with `xpc_error` (Sandbox restriction, error 159) and observer skipped (missing pid/process name).
- `smoke-8ecb378c-fd7f-443a-8575-b7faf951ed43`: `--capture-sandbox-logs` run; host capture failed with `missing child_pid for sandbox log capture`.
- `smoke-f0db6faf-1afb-429d-ba0d-720499effdbb`: manual observer (`--last 30s`); 27 records, 7 mapped denies. File operations mapped with `filter_inferred`; network-outbound mapped with explicit `remote` filter. Several permission-shaped failures had no deny evidence.
- `smoke-fd118439-a88a-44c6-954d-5c80afba9714`: manual observer with time-range + correlation id; only 6 mapped denies and minimal had none. Time-range window appears brittle.
- `smoke-dc03c1fb-270e-4a75-901c-6ecdfd557156`: manual observer (`--last 30s`) + correlation id; 27 records, 12 mapped denies across all three profiles. File operations mapped with `filter_inferred`; one explicit `remote` filter via `network-outbound`.
- Diff `smoke-f0db6faf-1afb-429d-ba0d-720499effdbb` vs `smoke-dc03c1fb-270e-4a75-901c-6ecdfd557156`: 7 row_ids flipped between hypothesis and mapped. `temporary_exception.net_op_tcp_connect_control` flipped from mapped → hypothesis; several `fs_op_listdir_home_*` rows flipped to mapped. Stability is not yet established.
