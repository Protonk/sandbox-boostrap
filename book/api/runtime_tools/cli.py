#!/usr/bin/env python3
"""
Unified CLI for runtime tools (harness generate + run).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import harness_generate as gen
from . import harness_runner as runner


def generate_command(args: argparse.Namespace) -> int:
    ROOT = Path(__file__).resolve().parents[2]
    matrix = args.matrix or ROOT / "experiments" / "runtime-checks" / "out" / "expected_matrix.json"
    runtime_results = args.runtime_results or ROOT / "experiments" / "runtime-checks" / "out" / "runtime_results.json"
    baseline_ref = args.baseline or "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"
    map_root = args.out or ROOT / "graph" / "mappings" / "runtime"
    decoded_blobs = map_root / "decoded_blobs"
    decode_summary = map_root / "golden_decodes.json"
    expectations = map_root / "golden_expectations.json"
    traces = map_root / "traces" / "golden_traces.jsonl"

    baseline = gen.load_baseline(baseline_ref)
    profiles = gen.load_matrix(matrix)
    decodes = []
    for key, prof in profiles.items():
        blob = gen.compile_profile(prof)
        out_blob = decoded_blobs / f"{key.replace(':', '_')}.sb.bin"
        out_blob.parent.mkdir(parents=True, exist_ok=True)
        out_blob.write_bytes(blob)
        decoded = gen.decode_profile(blob)
        decodes.append(gen.summarize_decode(key, prof.path, blob, decoded))
    gen.write_json(decode_summary, {"metadata": {"world_id": baseline.world_id}, "decodes": decodes})

    expectations_payload = {
        "metadata": {"world_id": baseline.world_id},
        "profiles": {
            key: {
                "blob": str(prof.path),
                "mode": prof.mode,
                "sha256": {d["key"]: d for d in decodes}[key]["sha256"],
            }
            for key, prof in profiles.items()
        },
    }
    gen.write_json(expectations, expectations_payload)

    traces_rows = gen.normalize_runtime_results(runtime_results, gen.GOLDEN_KEYS)
    gen.write_jsonl(traces, traces_rows)

    print(f"[+] wrote {decode_summary}")
    print(f"[+] wrote {expectations}")
    print(f"[+] wrote {traces}")
    return 0


def run_command(args: argparse.Namespace) -> int:
    out_path = runner.run_expected_matrix(args.matrix, out_dir=args.out)
    print(f"[+] wrote {out_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Runtime tools (generate mappings and run expected matrices).")
    sub = ap.add_subparsers(dest="command", required=True)

    ap_gen = sub.add_parser("generate", help="Generate golden decodes/expectations/traces from runtime-checks outputs.")
    ap_gen.add_argument("--matrix", type=Path, help="Path to expected_matrix.json (default: experiments/runtime-checks/out/expected_matrix.json)")
    ap_gen.add_argument("--runtime-results", type=Path, help="Path to runtime_results.json (default: experiments/runtime-checks/out/runtime_results.json)")
    ap_gen.add_argument("--baseline", type=Path, help="Path to world baseline JSON")
    ap_gen.add_argument("--out", type=Path, help="Root output directory for mappings (default: book/graph/mappings/runtime/)")
    ap_gen.set_defaults(func=generate_command)

    ap_run = sub.add_parser("run", help="Run runtime probes for an expected matrix (writes runtime_results.json).")
    ap_run.add_argument("--matrix", type=Path, default=runner.DEFAULT_OUT / "expected_matrix.json", help="Path to expected_matrix.json")
    ap_run.add_argument("--out", type=Path, default=runner.DEFAULT_OUT, help="Output directory (default: book/profiles/golden-triple/)")
    ap_run.set_defaults(func=run_command)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
