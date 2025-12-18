# sbpl_compile (deprecated)

Backward-compatibility shims for the former SBPL compiler helpers.

The canonical profile tooling surface is `book/api/profile_tools/`.

- `__init__.py` – shim exports (`compile_sbpl_file`, `compile_sbpl_string`, `hex_preview`) forwarding to `book.api.profile_tools`.
- `cli.py` – shim CLI entrypoint forwarding to `book.api.profile_tools.cli`.
- `c/compile_profile.c` – deprecated wrapper; canonical C reference lives at `book/api/profile_tools/c/compile_profile.c`.

Assumptions: baseline from `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`; `libsandbox.dylib` present. Outputs are the modern graph-based binary blobs described in `substrate/Appendix.md`.

New code should import from `book.api.profile_tools` instead of `book.api.sbpl_compile`.
