# Doctor (world baseline checkup)

Doctor performs a baseline integrity check of a candidate world baseline by
verifying dyld manifest integrity and comparing host identity signals.
Mapping path: none.

What it checks:
- world.json and dyld/manifest.json resolution (plus registry lookups)
- dyld manifest hash vs world_id suffix (and optional manifest.hash.json match)
- dyld libs existence, size, and sha256
- host identity signals (sw_vers, uname, csrutil)
- dyld shared cache presence and header UUID (best-effort)
- /tmp symlink and baseline knobs (tcc_state, profile_format_variant, apply_gates)
- optional compile/decode smoke profile

Usage (from repo root):

```sh
python3 book/tools/doctor/doctor.py --world sonoma-14.4.1-23E224-arm64
python3 book/tools/doctor/doctor.py --world book/world/sonoma-14.4.1-23E224-arm64/dyld/manifest.json --out book/tools/doctor/out/sonoma-14.4.1-23E224-arm64
```

Outputs:
- doctor_report.json
- doctor_witness.txt

Exit codes:
- 0: likely_match with baseline integrity ok
- 1: inconclusive or warnings
- 2: mismatch or baseline integrity error

Notes:
- Dyld cache UUID extraction uses a fixed header offset heuristic; treat it as best-effort.
- This tool does not update mappings or CARTON.
- World name/id lookups use `book/world/registry.json`.
