# Apple Scheme compiler demo

- Builds a tiny clang shim that calls `sandbox_compile_file` to turn `profiles/demo.sb` into a compiled blob (`build/demo.sb.bin`), mirroring the SBPL → TinyScheme → binary pipeline in `substrate/Orientation.md` §3.2.
- Output bytecode layout matches the header/op-table/node/regex/literal structure described in `substrate/Appendix.md`; feed the blob to decoders like `sbdis`, `re2dot`, or `resnarf`.
- The demo profile is intentionally permissive enough to compile/run the helper; adjust `profiles/demo.sb` to watch how changes in SBPL affect the compiled graph.
