# SBPL Compile Helpers

Canonical wrappers for the private `sandbox_compile_*` APIs on the Sonoma baseline.

- `__init__.py` – Python helpers (`compile_sbpl_file`, `compile_sbpl_string`, `hex_preview`).
- `cli.py` – CLI entrypoint (`python -m book.api.sbpl_compile.cli input.sb ...`).
- `c/compile_profile.c` – minimal C reference for parity with the Python path.

Assumptions: baseline from `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`; `libsandbox.dylib` present. Outputs are the modern graph-based binary blobs described in `substrate/Appendix.md`.

These helpers supersede the ad-hoc compilers in `book/examples/sbsnarf`, `book/examples/sb/compile_sample.py`, and `book/examples/extract_sbs/compile_profiles.py`. The original example scripts now shim into this module.
