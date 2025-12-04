"""
Golden triple runtime harness helpers.

Purpose: run expectation-driven probes for SBPL profiles and emit runtime_results.json
aligned with the provisional schema (expectation_id join key, structured runtime_result).

Default output location: book/profiles/golden-triple
Host baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_OUT = Path(__file__).resolve().parents[2] / "profiles" / "golden-triple"
DEFAULT_RUNTIME_PROFILE_DIR = DEFAULT_OUT / "runtime_profiles"
RUNNER = Path(__file__).resolve().parents[3] / "experiments" / "runtime-checks" / "sandbox_runner"
READER = Path(__file__).resolve().parents[3] / "experiments" / "runtime-checks" / "sandbox_reader"
WRAPPER = Path(__file__).resolve().parents[2] / "SBPL-wrapper" / "wrapper"

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
]


def ensure_tmp_files(fixture_root: Path = Path("/tmp")) -> None:
    """
    Create fixture files under fixture_root for read/write probes.
    """
    for name in ["foo", "bar"]:
        p = fixture_root / name
        p.write_text(f"runtime-checks {name}\n")
        (p.with_suffix(".txt")).write_text(f"{name}\n")
    (fixture_root / "baz.txt").write_text("baz\n")
    (fixture_root / "qux.txt").write_text("qux\n")
    rt = fixture_root / "sbpl_rt"
    rt.mkdir(parents=True, exist_ok=True)
    (rt / "read.txt").write_text("runtime-checks read\n")
    (rt / "write.txt").write_text("runtime-checks write\n")
    (rt / "param_root").mkdir(parents=True, exist_ok=True)
    (rt / "param_root" / "foo").write_text("runtime-checks param_root foo\n")


def classify_status(probes: List[Dict[str, Any]], skipped_reason: str | None = None) -> tuple[str, str | None]:
    """
    Map probe outcomes into the project-wide validation status vocabulary.
    """
    if skipped_reason:
        return "blocked", skipped_reason
    if not probes:
        return "blocked", "no probes executed"
    if any(p.get("error") for p in probes):
        return "blocked", "probe execution error"
    stderr_blob = " ".join((p.get("stderr") or "") for p in probes)
    if "Operation not permitted" in stderr_blob or "sandbox_apply" in stderr_blob or "sandbox initialization failed" in stderr_blob:
        return "blocked", "sandbox_init/sandbox_apply returned EPERM"
    all_match = all(p.get("match") is True for p in probes)
    if all_match:
        return "ok", None
    return "partial", "runtime results diverged from expected allow/deny matrix"


def prepare_runtime_profile(
    base: Path,
    key: str,
    key_specific_rules: Dict[str, List[str]],
    runtime_profile_dir: Path,
    shim_rules: List[str] | None = None,
    profile_mode: str | None = None,
) -> Path:
    """
    Create a runtime-ready SBPL profile that preserves the file policy but
    adds minimal shims (process-exec, core system file reads) so sandbox-exec can launch probe binaries.
    """
    runtime_profile_dir.mkdir(parents=True, exist_ok=True)
    if base.suffix == ".bin":
        return base
    text = base.read_text()
    runtime_path = runtime_profile_dir / f"{base.stem}.{key.replace(':', '_')}.runtime.sb"
    shim = "\n".join((shim_rules or RUNTIME_SHIM_RULES) + key_specific_rules.get(key, [])) + "\n"
    patched = text.rstrip() + "\n" + shim
    runtime_path.write_text(patched + ("\n" if not patched.endswith("\n") else ""))
    return runtime_path


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
        cmd = [SH, "-c", f"echo runtime-check >> '{target}'"]
    elif op == "process-exec":
        cmd = ["true"]
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


def run_expected_matrix(
    matrix_path: Path | str,
    out_dir: Path | None = None,
    runtime_profile_dir: Path | None = None,
    profile_paths: Dict[str, Path] | None = None,
    key_specific_rules: Dict[str, List[str]] | None = None,
) -> Path:
    """
    Run probes described in an expected_matrix.json and write runtime_results.json to out_dir.
    """
    matrix_path = Path(matrix_path)
    out_dir = Path(out_dir) if out_dir else DEFAULT_OUT
    runtime_profile_dir = Path(runtime_profile_dir) if runtime_profile_dir else out_dir / "runtime_profiles"
    ensure_tmp_files()
    assert matrix_path.exists(), f"missing expected matrix: {matrix_path}"
    matrix = json.loads(matrix_path.read_text())
    profiles = matrix.get("profiles") or {}
    profile_paths = profile_paths or {}
    key_specific_rules = key_specific_rules or {}

    results: Dict[str, Any] = {}
    for key, rec in profiles.items():
        profile_path = profile_paths.get(key)
        if not profile_path:
            blob = rec.get("blob")
            if blob:
                profile_path = Path(blob)
        if not profile_path or not profile_path.exists():
            status, note = classify_status([], skipped_reason="no profile path")
            entry: Dict[str, Any] = {"status": status}
            if note:
                entry["notes"] = note
            results[key] = entry
            continue
        runtime_profile = prepare_runtime_profile(
            profile_path,
            key,
            key_specific_rules=key_specific_rules,
            runtime_profile_dir=runtime_profile_dir,
            profile_mode=rec.get("mode"),
        )
        profile_mode = rec.get("mode")
        probes = rec.get("probes") or []
        probe_results = []
        for probe in probes:
            raw = run_probe(runtime_profile, probe, profile_mode)
            actual = "allow" if raw.get("exit_code") == 0 else "deny"
            expected = probe.get("expected")
            runtime_result = {
                "status": "success" if raw.get("exit_code") == 0 else "errno",
                "errno": raw.get("exit_code") if raw.get("exit_code") else None,
            }
            violation_summary = None
            if raw.get("stderr") and "Operation not permitted" in raw.get("stderr", ""):
                violation_summary = "EPERM"
            probe_results.append(
                {
                    "name": probe.get("name"),
                    "expectation_id": probe.get("expectation_id"),
                    "operation": probe.get("operation"),
                    "path": probe.get("target"),
                    "expected": expected,
                    "actual": actual,
                    "match": expected == actual,
                    "runtime_result": runtime_result,
                    "violation_summary": violation_summary,
                    **raw,
                }
            )
        status, note = classify_status(probe_results)
        entry = {
            "status": status,
            "profile_path": str(runtime_profile),
            "base_profile_path": str(profile_path),
            "probes": probe_results,
        }
        if note:
            entry["notes"] = note
        results[key] = entry

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "runtime_results.json"
    out_path.write_text(json.dumps(results, indent=2))
    return out_path

