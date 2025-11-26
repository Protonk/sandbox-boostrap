# SBPL to blob helper

- Minimal wrapper around `sandbox_compile_file` that turns an SBPL file into a compiled `.sb.bin` blob (SBPL → TinyScheme → binary graph per `substrate/Orientation.md` §3.2).
- Intended as the simplest feedstock generator for decoders (`sbdis`, `resnarf`, `re2dot`); it does not apply the sandbox or add parameters/entitlements.
- Blob layout follows the header/operation table/node/regex/literal structure in `substrate/Appendix.md`; inspect with the shared ingestion tooling if needed.
