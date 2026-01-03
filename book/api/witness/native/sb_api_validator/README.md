# sb_api_validator

Role: call `sandbox_check()` against a target PID with explicit filter types.

Use when: you need a second, low-noise oracle lane to compare against PolicyWitness or SBPL harnesses.

Build:

```sh
./build.sh
```

Usage:

```sh
./sb_api_validator --json <pid> <operation> <filter_type> <filter_value>
./sb_api_validator --json <pid>
./sb_api_validator --json <pid> --list-fds
```

Notes:
- Signed with `debug.ent` so cross-process `sandbox_check()` calls work.
- JSON output is emitted only with `--json`.
