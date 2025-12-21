# Notes

- Initialized experiment scaffold and harness layout.
- Built the interposer dylib via `harness/build_interposer.sh`.
- Interposer load failed: `dyld` aborts with `symbol not found in flat namespace '__sb_mutable_buffer_write'` when injecting into the compile process.
- Verified baseline compilation without interposer: `out/blobs/_debug.sb.bin` from `baseline/allow_all.sb`.
