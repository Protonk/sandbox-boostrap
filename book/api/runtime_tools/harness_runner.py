"""
Runtime execution harness for expected matrices.

Consolidated home for the former `golden_runner`.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from book.api.path_utils import ensure_absolute, find_repo_root, relativize_command, to_repo_relative
from book.api.runtime_tools import runtime_contract as rt_contract

REPO_ROOT = find_repo_root(Path(__file__))
DEFAULT_OUT = REPO_ROOT / "book" / "profiles" / "golden-triple"
DEFAULT_RUNTIME_PROFILE_DIR = DEFAULT_OUT / "runtime_profiles"
RUNNER = REPO_ROOT / "book" / "experiments" / "runtime-checks" / "sandbox_runner"
READER = REPO_ROOT / "book" / "experiments" / "runtime-checks" / "sandbox_reader"
WRITER = REPO_ROOT / "book" / "experiments" / "runtime-checks" / "sandbox_writer"
WRAPPER = REPO_ROOT / "book" / "api" / "SBPL-wrapper" / "wrapper"
MACH_PROBE = REPO_ROOT / "book" / "experiments" / "runtime-checks" / "mach_probe"

CAT = "/bin/cat"
SH = "/bin/sh"

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

def _first_marker(markers: List[Dict[str, Any]], stage: str) -> Optional[Dict[str, Any]]:
    for marker in markers:
        if marker.get("stage") == stage:
            return marker
    return None


_SHA256_CACHE: Dict[str, str] = {}


def _sha256_path(path: Path) -> str:
    key = str(path)
    cached = _SHA256_CACHE.get(key)
    if cached:
        return cached
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    _SHA256_CACHE[key] = digest
    return digest


def ensure_tmp_files(fixture_root: Path = Path("/tmp")) -> None:
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
    strict_dir = Path("/private/tmp/strict_ok")
    strict_dir.mkdir(parents=True, exist_ok=True)
    (strict_dir / "allow.txt").write_text("strict allow\n")
    ok_dir = Path("/private/tmp/ok")
    ok_dir.mkdir(parents=True, exist_ok=True)
    (ok_dir / "allow.txt").write_text("param ok allow\n")


def classify_status(probes: List[Dict[str, Any]], skipped_reason: str | None = None) -> tuple[str, str | None]:
    if skipped_reason:
        return "blocked", skipped_reason
    if not probes:
        return "blocked", "no probes executed"
    if any(p.get("error") for p in probes):
        return "blocked", "probe execution error"
    blocked_stages = {"apply", "bootstrap", "preflight"}
    stages = []
    for probe in probes:
        rr = probe.get("runtime_result") or {}
        stage = rr.get("failure_stage")
        if stage:
            stages.append(stage)
    if stages and all(stage in blocked_stages for stage in stages):
        return "blocked", "all probes blocked before policy evaluation"
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
    base = ensure_absolute(base, REPO_ROOT)
    runtime_profile_dir.mkdir(parents=True, exist_ok=True)
    if base.suffix == ".bin":
        return base
    text = base.read_text()
    runtime_path = runtime_profile_dir / f"{base.stem}.{key.replace(':', '_')}.runtime.sb"
    shim = "\n".join((shim_rules or RUNTIME_SHIM_RULES) + key_specific_rules.get(key, [])) + "\n"
    patched = text.rstrip() + "\n" + shim
    runtime_path.write_text(patched + ("\n" if not patched.endswith("\n") else ""))
    return runtime_path


def run_probe(profile: Path, probe: Dict[str, Any], profile_mode: str | None, wrapper_preflight: str | None) -> Dict[str, Any]:
    target = probe.get("target")
    op = probe.get("operation")
    cmd: List[str]
    blob_mode = (probe.get("mode") == "blob") or (profile_mode == "blob")
    if profile.suffix == ".bin" and WRAPPER.exists():
        blob_mode = True

    reader_mode = False
    writer_mode = False
    if op == "file-read*":
        # In blob mode, the wrapper applies the compiled profile; use /bin/cat
        # as the in-sandbox probe so we don't re-run sandbox_init on a .sb.bin.
        if not blob_mode and READER.exists():
            cmd = [str(READER), str(profile), target]
            reader_mode = True
        else:
            cmd = [CAT, target]
    elif op == "file-write*":
        # Same rule as file-read*: avoid sandbox_init-on-binary by using /bin/sh
        # inside the blob-applied wrapper process.
        if not blob_mode and WRITER.exists():
            cmd = [str(WRITER), str(profile), target]
            writer_mode = True
        else:
            cmd = [SH, "-c", f"echo runtime-check >> '{target}'"]
    elif op == "mach-lookup":
        if MACH_PROBE.exists():
            cmd = [str(MACH_PROBE), target]
        else:
            cmd = ["true"]
    elif op == "network-outbound":
        hostport = target or "127.0.0.1"
        if ":" in hostport:
            host, port = hostport.split(":", 1)
        else:
            host, port = hostport, "80"
        nc = Path("/usr/bin/nc")
        cmd = [str(nc), "-z", "-w", "2", host, port]
    elif op == "process-exec":
        cmd = ["true"]
    else:
        cmd = ["true"]

    if blob_mode and WRAPPER.exists():
        full_cmd = [str(WRAPPER)]
        if wrapper_preflight:
            full_cmd += ["--preflight", wrapper_preflight]
        full_cmd += ["--blob", str(profile), "--"] + cmd
    elif reader_mode:
        full_cmd = cmd
    elif writer_mode:
        full_cmd = cmd
    elif RUNNER.exists():
        full_cmd = [str(RUNNER), str(profile), "--"] + cmd
    else:
        return {"error": "sandbox_runner missing; sandbox-exec fallback is unsupported for stable runtime IR"}

    env = None
    if os.environ.get("SANDBOX_LORE_SEATBELT_CALLOUT") == "1":
        filter_type: Optional[int] = None
        callout_arg: Optional[str] = None
        if op in {"file-read*", "file-write*", "file-read-metadata"} and target:
            filter_type = 0
            callout_arg = target
        elif op == "mach-lookup" and target:
            filter_type = 5
            callout_arg = target

        if op and filter_type is not None and callout_arg is not None:
            env = dict(os.environ)
            env["SANDBOX_LORE_SEATBELT_OP"] = op
            env["SANDBOX_LORE_SEATBELT_FILTER_TYPE"] = str(filter_type)
            env["SANDBOX_LORE_SEATBELT_ARG"] = callout_arg

    try:
        res = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
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
    matrix_path = ensure_absolute(matrix_path, REPO_ROOT)
    out_dir = ensure_absolute(out_dir, REPO_ROOT) if out_dir else DEFAULT_OUT
    runtime_profile_dir = ensure_absolute(runtime_profile_dir, REPO_ROOT) if runtime_profile_dir else out_dir / "runtime_profiles"
    ensure_tmp_files()
    assert matrix_path.exists(), f"missing expected matrix: {matrix_path}"
    matrix = json.loads(matrix_path.read_text())
    profiles = matrix.get("profiles") or {}
    profile_paths = {k: ensure_absolute(v, REPO_ROOT) for k, v in (profile_paths or {}).items()}
    key_specific_rules = key_specific_rules or {}

    results: Dict[str, Any] = {}
    preflight_enabled = os.environ.get("SANDBOX_LORE_PREFLIGHT") != "0"
    preflight_force = os.environ.get("SANDBOX_LORE_PREFLIGHT_FORCE") == "1"
    for key, rec in profiles.items():
        profile_path = profile_paths.get(key)
        if not profile_path:
            blob = rec.get("blob")
            if blob:
                profile_path = ensure_absolute(blob, REPO_ROOT)
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
        preflight_record: Optional[Dict[str, Any]] = None
        preflight_blocked = False
        profile_preflight_mode = rec.get("preflight")
        if isinstance(profile_preflight_mode, dict):
            profile_preflight_mode = profile_preflight_mode.get("mode")
        if isinstance(profile_preflight_mode, str):
            profile_preflight_mode = profile_preflight_mode.strip().lower()
        else:
            profile_preflight_mode = None

        profile_preflight_enabled = preflight_enabled
        profile_preflight_force = preflight_force
        if profile_preflight_mode == "off":
            profile_preflight_enabled = False
        elif profile_preflight_mode == "force":
            profile_preflight_enabled = True
            profile_preflight_force = True
        elif profile_preflight_mode == "enforce":
            profile_preflight_enabled = True
            profile_preflight_force = False

        supported_preflight_input = runtime_profile.suffix == ".sb" or runtime_profile.suffixes[-2:] == [".sb", ".bin"]
        if profile_preflight_enabled and supported_preflight_input:
            try:
                from book.tools.preflight import preflight as preflight_mod  # type: ignore

                rec_obj = preflight_mod.preflight_path(runtime_profile)
                preflight_record = rec_obj.to_json()
                if (
                    preflight_record.get("classification") == "likely_apply_gated_for_harness_identity"
                    and not profile_preflight_force
                ):
                    preflight_blocked = True
            except Exception:
                preflight_record = None
                preflight_blocked = False
        probes = rec.get("probes") or []
        probe_results = []
        for probe in probes:
            if preflight_blocked:
                actual = None
                raw = {"command": [], "exit_code": None, "stdout": "", "stderr": ""}
            else:
                wrapper_preflight = None
                if not profile_preflight_enabled:
                    wrapper_preflight = "off"
                elif profile_preflight_force:
                    wrapper_preflight = "force"
                else:
                    wrapper_preflight = "enforce"
                raw = run_probe(runtime_profile, probe, profile_mode, wrapper_preflight)
                actual = "allow" if raw.get("exit_code") == 0 else "deny"
            expected = probe.get("expected")

            stderr = raw.get("stderr") or ""
            apply_markers = rt_contract.extract_sbpl_apply_markers(stderr)
            apply_marker = _first_marker(apply_markers, "apply")
            applied_marker = _first_marker(apply_markers, "applied")
            exec_marker = _first_marker(apply_markers, "exec")
            seatbelt_callouts = rt_contract.extract_seatbelt_callout_markers(stderr) or None

            failure_stage: Optional[str] = None
            failure_kind: Optional[str] = None
            observed_errno: Optional[int] = None
            apply_report: Optional[Dict[str, Any]] = None

            if preflight_blocked:
                failure_stage = "preflight"
                failure_kind = "preflight_apply_gate_signature"
            apply_rc = apply_marker.get("rc") if apply_marker else None
            if isinstance(apply_rc, int) and apply_rc != 0:
                failure_stage = "apply"
                if apply_marker:
                    api = apply_marker.get("api")
                    errbuf = apply_marker.get("errbuf")
                    err_class = apply_marker.get("err_class")
                    apply_report = {
                        "api": api,
                        "rc": apply_marker.get("rc"),
                        "errno": apply_marker.get("errno"),
                        "errbuf": errbuf,
                        "err_class": err_class,
                        "err_class_source": apply_marker.get("err_class_source"),
                    }
                    if err_class == "already_sandboxed":
                        failure_kind = "apply_already_sandboxed"
                    else:
                        failure_kind = f"{api}_failed" if api else "apply_failed"
                else:
                    failure_kind = "apply_failed"
                observed_errno = apply_marker.get("errno") if apply_marker else None
            else:
                if apply_marker:
                    apply_report = {
                        "api": apply_marker.get("api"),
                        "rc": apply_marker.get("rc"),
                        "errno": apply_marker.get("errno"),
                        "errbuf": apply_marker.get("errbuf"),
                        "err_class": apply_marker.get("err_class"),
                        "err_class_source": apply_marker.get("err_class_source"),
                    }
                exec_rc = exec_marker.get("rc") if exec_marker else None
                if isinstance(exec_rc, int) and exec_rc != 0:
                    failure_stage = "bootstrap"
                    observed_errno = exec_marker.get("errno") if exec_marker else None
                    if applied_marker is not None and observed_errno == 1:
                        failure_kind = "bootstrap_deny_process_exec"
                    else:
                        failure_kind = "bootstrap_exec_failed"
                elif raw.get("exit_code") not in (None, 0):
                    failure_stage = "probe"
                    failure_kind = "probe_nonzero_exit"
                    observed_errno = observed_errno or raw.get("exit_code")

            entrypoint = (raw.get("command") or [None])[0]
            entrypoint_path = Path(entrypoint) if isinstance(entrypoint, str) else None
            runner_info: Optional[Dict[str, Any]]
            if entrypoint == str(WRAPPER):
                runner_info = {"entrypoint": "SBPL-wrapper", "apply_model": "exec_wrapper", "apply_timing": "pre_exec"}
            elif entrypoint == str(RUNNER):
                runner_info = {"entrypoint": "sandbox_runner", "apply_model": "exec_wrapper", "apply_timing": "pre_exec"}
            elif entrypoint == str(READER):
                runner_info = {"entrypoint": "sandbox_reader", "apply_model": "self_apply", "apply_timing": "pre_syscall"}
            elif entrypoint == str(WRITER):
                runner_info = {"entrypoint": "sandbox_writer", "apply_model": "self_apply", "apply_timing": "pre_syscall"}
            else:
                runner_info = None

            if runner_info is not None:
                runner_info["preexisting_sandbox_suspected"] = failure_kind == "apply_already_sandboxed"

            if runner_info is not None and entrypoint_path and entrypoint_path.exists():
                runner_info["entrypoint_path"] = to_repo_relative(entrypoint_path, REPO_ROOT)
                runner_info["entrypoint_sha256"] = _sha256_path(entrypoint_path)
                runner_info["tool_build_id"] = runner_info["entrypoint_sha256"]

            runtime_result = {
                "status": "blocked" if preflight_blocked else ("success" if raw.get("exit_code") == 0 else "errno"),
                "errno": None if preflight_blocked or raw.get("exit_code") == 0 else observed_errno,
                "runtime_result_schema_version": rt_contract.CURRENT_RUNTIME_RESULT_SCHEMA_VERSION,
                "tool_marker_schema_version": rt_contract.CURRENT_TOOL_MARKER_SCHEMA_VERSION,
                "failure_stage": failure_stage,
                "failure_kind": failure_kind,
                "apply_report": apply_report,
                "runner_info": runner_info,
                "seatbelt_callouts": seatbelt_callouts,
            }

            violation_summary = None
            if failure_stage in {"apply", "bootstrap"} and observed_errno == 1:
                violation_summary = "EPERM"
            elif (
                failure_stage == "apply"
                and isinstance(apply_report, dict)
                and apply_report.get("err_class") == "errno_eperm"
            ):
                violation_summary = "EPERM"

            probe_results.append(
                {
                    "name": probe.get("name"),
                    "expectation_id": probe.get("expectation_id"),
                    "operation": probe.get("operation"),
                    "path": probe.get("target"),
                    "expected": expected,
                    "actual": actual,
                    "match": (expected == actual) if actual is not None else None,
                    "runtime_result": runtime_result,
                    "violation_summary": violation_summary,
                    **{**raw, "command": relativize_command(raw.get("command") or [], REPO_ROOT)},
                    **(
                        {"notes": "preflight blocked: known apply-gate signature"}
                        if preflight_blocked
                        else {}
                    ),
                }
            )
        status, note = classify_status(probe_results)
        entry = {
            "status": status,
            "profile_path": to_repo_relative(runtime_profile, REPO_ROOT),
            "base_profile_path": to_repo_relative(profile_path, REPO_ROOT),
            "preflight": preflight_record,
            "probes": probe_results,
        }
        if note:
            entry["notes"] = note
        results[key] = entry

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "runtime_results.json"
    out_path.write_text(json.dumps(results, indent=2))
    return out_path
