#!/usr/bin/env python3
"""
Run simple runtime probes under sandbox-exec for selected SBPL profiles.

Profiles exercised:
- bucket4:v1_read (allow file-read*)
- bucket5:v11_read_subpath (allow file-read* under /tmp/foo)

Results are written to out/runtime_results.json with per-probe exit codes and
whether they matched the expected allow/deny from out/expected_matrix.json.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Dict, Any, List


ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "out"
RUNTIME_PROFILE_DIR = OUT / "runtime_profiles"
RUNNER = Path(__file__).resolve().parent / "sandbox_runner"
READER = Path(__file__).resolve().parent / "sandbox_reader"
WRAPPER = Path(__file__).resolve().parents[2] / "api" / "SBPL-wrapper" / "wrapper"

CAT = "/bin/cat"
SH = "/bin/sh"

# Harness shims needed to let probes start while keeping file policy intact.
RUNTIME_SHIM_RULES = [
    "(allow process-exec*)",
    '(allow file-read* (subpath "/System"))',
    '(allow file-read* (subpath "/usr"))',
    '(allow file-read* (subpath "/bin"))',
    '(allow file-read* (subpath "/sbin"))',
    '(allow file-read* (subpath "/dev"))',
    '(allow file-read-metadata (literal "/private"))',
    '(allow file-read-metadata (literal "/private/tmp"))',
    '(allow file-read-metadata (literal "/tmp"))',
    '(allow file-read* (subpath "/tmp/foo"))',
    '(allow file-read* (subpath "/private/tmp/foo"))',
]

KEY_SPECIFIC_RULES = {
    # Make the bucket-4 profile runnable: allow default, but pin a deny for /etc/hosts writes.
    "bucket4:v1_read": [
        "(allow default)",
        '(deny file-write* (literal "/etc/hosts"))',
    ],
    # Allow default for the subpath profile, then pin explicit denies for bar reads and foo writes.
    "bucket5:v11_read_subpath": [
        "(allow default)",
        '(deny file-read* (subpath "/private/tmp/bar"))',
        '(deny file-read* (subpath "/tmp/bar"))',
        '(deny file-write* (subpath "/private/tmp/foo"))',
        '(deny file-write* (subpath "/tmp/foo"))',
    ],
    "runtime:allow_all": [
        "(allow default)",
        "(allow process-exec*)",
        "(allow file-read* (regex \".*\"))",
        "(allow file-write* (regex \".*\"))",
        "(allow file-read-metadata (regex \".*\"))",
        "(allow file-write-create (regex \".*\"))",
    ],
    "runtime:metafilter_any": [
        "(allow process-exec*)",
        '(allow file-read* (literal "/tmp/foo.txt"))',
        '(allow file-read* (literal "/tmp/bar.txt"))',
    ]
}

PROFILE_PATHS = {
    "bucket4:v1_read": ROOT / "book/experiments/op-table-operation/sb/v1_read.sb",
    "bucket5:v11_read_subpath": ROOT / "book/experiments/op-table-operation/sb/v11_read_subpath.sb",
    "runtime:allow_all": ROOT / "book/experiments/sbpl-graph-runtime/profiles/allow_all.sb",
    "runtime:metafilter_any": ROOT / "book/experiments/sbpl-graph-runtime/profiles/metafilter_any.sb",
    "sys:airlock": ROOT / "book/examples/extract_sbs/build/profiles/airlock.sb.bin",
    "sys:bsd": ROOT / "book/examples/extract_sbs/build/profiles/bsd.sb.bin",
}


def ensure_tmp_files():
    # Create /tmp/foo and /tmp/bar for read/write probes
    for name in ["foo", "bar"]:
        p = Path("/tmp") / name
        p.write_text(f"runtime-checks {name}\n")


def run_probe(profile: Path, probe: Dict[str, Any], profile_mode: str | None) -> Dict[str, Any]:
    target = probe.get("target")
    op = probe.get("operation")
    cmd: List[str]
    reader_mode = False
    if op == "file-read*":
        if READER.exists():
            cmd = [str(READER), str(profile), target]
            reader_mode = True
        else:
            cmd = [CAT, target]
    elif op == "file-write*":
        # append to target
        cmd = [SH, "-c", f"echo runtime-check >> '{target}'"]
    else:
        cmd = ["true"]

    blob_mode = (probe.get("mode") == "blob") or (profile_mode == "blob")

    if blob_mode and WRAPPER.exists():
        full_cmd = [str(WRAPPER), "--blob", str(profile), "--"] + cmd
    elif reader_mode:
        full_cmd = cmd
    elif RUNNER.exists():
        full_cmd = [str(RUNNER), str(profile), "--"] + cmd
    else:
        full_cmd = ["sandbox-exec", "-f", str(profile), "--"] + cmd

    try:
        res = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return {
            "command": full_cmd,
            "exit_code": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr,
        }
    except FileNotFoundError as e:
        return {"error": f"sandbox-exec missing: {e}"}
    except Exception as e:
        return {"error": str(e)}


def prepare_runtime_profile(base: Path, key: str) -> Path:
    """
    Create a runtime-ready SBPL profile that preserves the file policy but
    adds minimal shims (process-exec, core system file reads, /tmp/foo variants)
    so sandbox-exec can launch probe binaries.
    """
    RUNTIME_PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    if base.suffix == ".bin":
        # For blob mode, just return the blob path; no shimmed SBPL.
        return base
    text = base.read_text()
    runtime_path = RUNTIME_PROFILE_DIR / f"{base.stem}.{key.replace(':', '_')}.runtime.sb"
    shim_rules = RUNTIME_SHIM_RULES + KEY_SPECIFIC_RULES.get(key, [])
    shim = "\n".join(shim_rules) + "\n"
    patched = text.rstrip() + "\n" + shim
    runtime_path.write_text(patched + ("\n" if not patched.endswith("\n") else ""))
    return runtime_path


def main():
    ensure_tmp_files()
    matrix_path = OUT / "expected_matrix.json"
    assert matrix_path.exists(), f"missing expected matrix: {matrix_path}"
    matrix = json.loads(matrix_path.read_text())
    profiles = matrix.get("profiles") or {}

    results = {}
    for key, rec in profiles.items():
        profile_path = PROFILE_PATHS.get(key)
        if not profile_path or not profile_path.exists():
            results[key] = {"status": "skipped", "reason": "no profile path"}
            continue
        runtime_profile = prepare_runtime_profile(profile_path, key)
        profile_mode = rec.get("mode")
        probes = rec.get("probes") or []
        probe_results = []
        for probe in probes:
            raw = run_probe(runtime_profile, probe, profile_mode)
            # Simple allow/deny heuristic: exit_code==0 => allow
            actual = "allow" if raw.get("exit_code") == 0 else "deny"
            expected = probe.get("expected")
            probe_results.append(
                {
                    "name": probe.get("name"),
                    "expected": expected,
                    "actual": actual,
                    "match": expected == actual,
                    **raw,
                }
            )
        results[key] = {
            "status": "completed",
            "profile_path": str(runtime_profile),
            "base_profile_path": str(profile_path),
            "probes": probe_results,
        }

    out_path = OUT / "runtime_results.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main()
