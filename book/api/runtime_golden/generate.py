#!/usr/bin/env python3
"""
Generate promoted golden artifacts from runtime-checks outputs.

Inputs:
- book/experiments/runtime-checks/out/expected_matrix.json
- book/experiments/runtime-checks/out/runtime_results.json
- SBPL/compiled profiles referenced by the golden set.

Outputs under book/graph/mappings/runtime/:
- golden_decodes.json
- decoded_blobs/<key>.sb.bin
- golden_expectations.json (manifest of profiles and probe defs)
- traces/golden_traces.jsonl
"""

from __future__ import annotations

import json
from pathlib import Path

from book.api.runtime_golden import (
    load_baseline,
    GOLDEN_KEYS,
    compile_profile,
    decode_profile,
    load_matrix,
    normalize_runtime_results,
    summarize_decode,
    write_json,
    write_jsonl,
)


ROOT = Path(__file__).resolve().parents[2]
EXP = ROOT / "experiments" / "runtime-checks"
MATRIX = EXP / "out" / "expected_matrix.json"
RUNTIME_RESULTS = EXP / "out" / "runtime_results.json"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"

MAP_ROOT = ROOT / "graph" / "mappings" / "runtime"
DECODED_BLOBS = MAP_ROOT / "decoded_blobs"
DECODE_SUMMARY = MAP_ROOT / "golden_decodes.json"
EXPECTATIONS = MAP_ROOT / "golden_expectations.json"
TRACES = MAP_ROOT / "traces" / "golden_traces.jsonl"


def main() -> int:
    baseline = load_baseline(BASELINE_REF)
    profiles = load_matrix(MATRIX)
    decodes = []
    for key, prof in profiles.items():
        blob = compile_profile(prof)
        out_blob = DECODED_BLOBS / f"{key.replace(':', '_')}.sb.bin"
        out_blob.parent.mkdir(parents=True, exist_ok=True)
        out_blob.write_bytes(blob)
        decoded = decode_profile(blob)
        decodes.append(summarize_decode(key, prof.path, blob, decoded))
    write_json(DECODE_SUMMARY, {"metadata": {"world_id": baseline.world_id}, "decodes": decodes})

    # expectations manifest
    expectations_payload = {
        "metadata": {"world_id": baseline.world_id},
        "profiles": {
            key: {
                "blob": str(prof.path),
                "mode": prof.mode,
                "sha256": decodes_dict[key]["sha256"],
            }
            for key, prof, decodes_dict in [
                (k, profiles[k], {d["key"]: d for d in decodes})
                for k in GOLDEN_KEYS
            ]
        }
    }
    write_json(EXPECTATIONS, expectations_payload)

    # traces from runtime_results.json (coarse)
    traces_rows = normalize_runtime_results(RUNTIME_RESULTS, GOLDEN_KEYS)
    write_jsonl(TRACES, traces_rows)

    print(f"[+] wrote {DECODE_SUMMARY}")
    print(f"[+] wrote {EXPECTATIONS}")
    print(f"[+] wrote {TRACES}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
