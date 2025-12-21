"""
Run entitlement-diff probes under an App Sandbox parent (EntitlementJail).

This runner is a second runtime witness alongside run_probes.py:
- It is witness-shaped: repeatable, provenance-carrying, and ruthless about "blocked".
- It stages all binaries under an observed HOME anchor and runs with cwd=stage_root.
- It never reinterprets "couldn't run" as "deny"; it classifies each attempt as
  executed | blocked | harness_error.

Outputs:
- out/jail_env_probe.json
- out/jail_runtime_results.json
- out/jail_entitlements.json
- out/jail_parity_summary.json
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from book.api.path_utils import find_repo_root, relativize_command, to_repo_relative
from book.api.profile_tools.identity import baseline_world_id


def _load_probe_plan():
    here = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("entitlement_diff.probe_plan", here / "probe_plan.py")
    if spec is None or spec.loader is None:
        raise ImportError("Failed to load probe_plan.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


probe_plan = _load_probe_plan()


REPO_ROOT = find_repo_root(Path(__file__))
WORLD_ID = baseline_world_id(REPO_ROOT)

ENTITLEMENT_JAIL = (
    REPO_ROOT
    / "book"
    / "tools"
    / "entitlement"
    / "EntitlementJail.app"
    / "Contents"
    / "MacOS"
    / "entitlement-jail"
)

OUT_DIR = REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "out"
WRAPPER_RESULTS_PATH = OUT_DIR / "runtime_results.json"

JAIL_ENV_PROBE_PATH = OUT_DIR / "jail_env_probe.json"
JAIL_RUNTIME_RESULTS_PATH = OUT_DIR / "jail_runtime_results.json"
JAIL_ENTITLEMENTS_PATH = OUT_DIR / "jail_entitlements.json"
JAIL_PARITY_SUMMARY_PATH = OUT_DIR / "jail_parity_summary.json"

LOG_STREAM_PREDICATE_SANDBOXD_AMFID = (
    '(process == "kernel" AND (eventMessage CONTAINS[c] "Sandbox:" OR eventMessage CONTAINS[c] "deny("))'
    ' OR (process == "sandboxd") OR (process == "amfid")'
)


_SHA256_CACHE: Dict[str, str] = {}


def _sha256_path(path: Path) -> str:
    key = str(path)
    cached = _SHA256_CACHE.get(key)
    if cached:
        return cached
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    _SHA256_CACHE[key] = digest
    return digest


def _try_read_text(path: Path, *, limit: int = 1_000_000) -> Optional[str]:
    try:
        data = path.read_text(errors="replace")
    except FileNotFoundError:
        return None
    if len(data) > limit:
        return data[:limit] + "\n[...truncated...]\n"
    return data


def _mkdir(path: Path) -> Optional[str]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        return None
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


def _chmod_plus_x(path: Path) -> Optional[str]:
    try:
        st = path.stat()
        mode = st.st_mode
        path.chmod(mode | 0o111)
        return None
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


def _stat_path(path: Path) -> Dict[str, Any]:
    try:
        st = path.stat()
        mode = st.st_mode & 0o777
        return {
            "exists": True,
            "is_file": path.is_file(),
            "is_dir": path.is_dir(),
            "mode": oct(mode),
            "size": st.st_size,
        }
    except FileNotFoundError:
        return {"exists": False}
    except Exception as exc:
        return {"exists": None, "error": f"{type(exc).__name__}: {exc}"}


def _run_subprocess(cmd: List[str], *, cwd: Optional[Path] = None, timeout: int = 20) -> Dict[str, Any]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(cwd) if cwd else None, timeout=timeout)
        return {
            "command": relativize_command(cmd, REPO_ROOT),
            "cwd": str(cwd) if cwd else None,
            "exit_code": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr,
        }
    except Exception as exc:
        return {
            "command": relativize_command(cmd, REPO_ROOT),
            "cwd": str(cwd) if cwd else None,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _parse_env_block(env_stdout: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in (env_stdout or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        out[key] = value
    return out


def _deterministic_run_id() -> str:
    parts: List[str] = [WORLD_ID, _sha256_path(ENTITLEMENT_JAIL)]
    for spec in probe_plan.staged_binary_specs(REPO_ROOT):
        parts.append(f"{spec.id}:{_sha256_path(spec.src_path)}")
    digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def _capture_under_jail(
    *,
    stage_root: Path,
    capture_root: Optional[Path] = None,
    attempt_id: str,
    command: List[str],
    timeout_s: float = 15.0,
) -> Dict[str, Any]:
    """
    Launch `command` under EntitlementJail, capturing stdout/stderr/rc to files under stage_root.

    EntitlementJail does not reliably forward stdout/stderr or wait for completion, so this function
    writes evidence to files and polls for a done marker.
    """

    jail_out = capture_root or (stage_root / "jail_out")
    mkdir_error = _mkdir(jail_out)
    if mkdir_error is not None:
        return {
            "classification": "harness_error",
            "failure_kind": "HOST_STAGE_ROOT_UNWRITABLE",
            "stage_root": str(stage_root),
            "capture_root": str(jail_out),
            "attempt_id": attempt_id,
            "mkdir_error": mkdir_error,
        }

    base = jail_out / attempt_id
    stdout_path = Path(str(base) + ".stdout")
    stderr_path = Path(str(base) + ".stderr")
    rc_path = Path(str(base) + ".rc")
    done_path = Path(str(base) + ".done")
    command0 = Path(command[0]) if command else None

    for p in [stdout_path, stderr_path, rc_path, done_path]:
        try:
            p.unlink(missing_ok=True)  # py3.8+: exists in 3.11 on host
        except TypeError:  # pragma: no cover - for older runtimes
            if p.exists():
                p.unlink()
        except Exception:
            # best-effort cleanup; keep going and let classification handle
            pass

    sh_script = (
        'stage="$1"; out="$2"; err="$3"; rc="$4"; done="$5"; shift 5; '
        'cd "$stage" 2>/dev/null || exit 97; '
        '"$@" >"$out" 2>"$err"; printf "%s\\n" "$?" >"$rc"; printf "done\\n" >"$done";'
    )

    sh_cmd = [
        "/bin/sh",
        "-c",
        sh_script,
        "sh",
        str(stage_root),
        str(stdout_path),
        str(stderr_path),
        str(rc_path),
        str(done_path),
        *command,
    ]

    jail_cmd = [str(ENTITLEMENT_JAIL), *sh_cmd]
    launch = _run_subprocess(jail_cmd, cwd=stage_root, timeout=10)

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if done_path.exists():
            break
        time.sleep(0.05)

    stdout_text = _try_read_text(stdout_path)
    stderr_text = _try_read_text(stderr_path)
    rc_text = _try_read_text(rc_path)
    done_text = _try_read_text(done_path)

    host_fs: Dict[str, Any] = {
        "stage_root": _stat_path(stage_root),
        "capture_root": _stat_path(jail_out),
        "command0": _stat_path(command0) if command0 is not None else None,
        "stdout_path": _stat_path(stdout_path),
        "stderr_path": _stat_path(stderr_path),
        "rc_path": _stat_path(rc_path),
        "done_path": _stat_path(done_path),
    }

    capture = {
        "attempt_id": attempt_id,
        "stage_root": str(stage_root),
        "capture_root": str(jail_out),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "rc_path": str(rc_path),
        "done_path": str(done_path),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "rc_text": rc_text,
        "done_text": done_text,
        "timeout_s": timeout_s,
        "host_fs": host_fs,
    }

    if not done_path.exists():
        return {
            "classification": "blocked",
            "failure_kind": "JAIL_LAUNCH_TIMEOUT",
            "command": relativize_command(command, REPO_ROOT),
            "jail_launch": launch,
            "capture": capture,
        }

    try:
        rc = int((rc_text or "").strip())
    except Exception:
        return {
            "classification": "harness_error",
            "failure_kind": "CAPTURE_RC_PARSE_FAILED",
            "command": command,
            "jail_launch": launch,
            "capture": capture,
        }

    blocked_reason = _classify_blocked_from_capture(rc, stderr_text)
    if blocked_reason is not None:
        return {
            "classification": "blocked",
            "failure_kind": blocked_reason,
            "command": relativize_command(command, REPO_ROOT),
            "exit_code": rc,
            "jail_launch": launch,
            "capture": capture,
        }

    return {
        "classification": "executed",
        "command": relativize_command(command, REPO_ROOT),
        "exit_code": rc,
        "jail_launch": launch,
        "capture": capture,
    }


def _classify_blocked_from_capture(exit_code: int, stderr_text: Optional[str]) -> Optional[str]:
    """
    Best-effort blocked classification for exec/cwd/dyld style failures.

    This intentionally does NOT treat syscall-level EPERM in probe stderr (e.g., "bind: Operation not permitted")
    as blocked; those are executed probes with deny outcomes.
    """

    if exit_code == 126:
        return "JAIL_EXEC_FAILED"
    if exit_code == 127:
        return "JAIL_EXEC_NOT_FOUND"

    text = (stderr_text or "").lower()
    if "dyld" in text and ("library not loaded" in text or "symbol not found" in text):
        return "DYLD_LOAD_FAILED"
    if "getcwd" in text and "failed" in text:
        return "JAIL_CWD_UNUSABLE"

    return None


def _parse_json_line(text: Optional[str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not text:
        return None, "empty"
    # many probes print exactly one JSON line
    line = text.strip().splitlines()[-1].strip()
    if not (line.startswith("{") and line.endswith("}")):
        return None, "non_json"
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        return None, f"json_decode_error:{exc}"
    if not isinstance(obj, dict):
        return None, "json_not_object"
    return obj, None


def _normalize_probe_outcome(probe_id: str, executed: Mapping[str, Any]) -> Dict[str, Any]:
    exit_code = executed.get("exit_code")
    stdout = ((executed.get("capture") or {}).get("stdout") if isinstance(executed.get("capture"), dict) else None) or ""
    stderr = ((executed.get("capture") or {}).get("stderr") if isinstance(executed.get("capture"), dict) else None) or ""

    normalized: Dict[str, Any] = {
        "probe_id": probe_id,
        "classification": executed.get("classification"),
        "exit_code": exit_code,
    }

    if probe_id == "mach_lookup_cfprefsd_agent":
        obj, err = _parse_json_line(stdout)
        if err is not None:
            normalized.update({"parse_error": err, "decision": None})
            return normalized
        kr = obj.get("kr") if isinstance(obj, dict) else None
        normalized["kr"] = kr
        normalized["decision"] = "allow" if kr == 0 else "deny"
        return normalized

    if probe_id in {"file_read", "file_write"}:
        obj, err = _parse_json_line(stdout)
        if err is not None:
            normalized.update({"parse_error": err, "decision": None})
            return normalized
        rc = obj.get("rc")
        err_no = obj.get("errno")
        normalized["rc"] = rc
        normalized["errno"] = err_no
        normalized["decision"] = "allow" if rc == 0 else "deny"
        return normalized

    if probe_id in {"network_bind", "network_outbound_localhost"}:
        # These probes are not structured; treat exit_code==0 as allow.
        normalized["decision"] = "allow" if exit_code == 0 else "deny"
        if stderr:
            normalized["stderr_hint"] = stderr.strip().splitlines()[-1]
        return normalized

    normalized["decision"] = "allow" if exit_code == 0 else "deny"
    return normalized


def _codesign_entitlements(path: Path) -> Dict[str, Any]:
    # codesign prints "Executable=..." to stderr; keep both streams as evidence.
    res = _run_subprocess(["/usr/bin/codesign", "-d", "--entitlements", "-", str(path)], timeout=20)
    return {"command": res.get("command"), "exit_code": res.get("exit_code"), "stdout": res.get("stdout"), "stderr": res.get("stderr")}


def _codesign_verbose(path: Path) -> Dict[str, Any]:
    res = _run_subprocess(["/usr/bin/codesign", "-dv", "--verbose=4", str(path)], timeout=20)
    # codesign -dv writes almost everything to stderr
    return {"command": res.get("command"), "exit_code": res.get("exit_code"), "stdout": res.get("stdout"), "stderr": res.get("stderr")}


def _parse_codesign_kv(stderr_text: Optional[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in (stderr_text or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            out[key] = value
    return out


def _extract_parent_and_child_entitlements(stage_root: Path) -> Dict[str, Any]:
    staged = probe_plan.staged_destinations(stage_root, REPO_ROOT)
    binaries: Dict[str, Path] = {
        "parent_entitlement_jail": ENTITLEMENT_JAIL,
        "child_entitlement_sample": staged["entitlement_sample"],
        "child_entitlement_sample_unsigned": staged["entitlement_sample_unsigned"],
        "child_mach_probe": staged["mach_probe"],
        "child_file_probe": staged["file_probe"],
    }
    out: Dict[str, Any] = {"world_id": WORLD_ID, "binaries": {}}
    for label, path in binaries.items():
        entry: Dict[str, Any] = {
            "path": str(path),
            "sha256": None,
            "codesign_verbose": None,
            "codesign_kv": None,
            "codesign_entitlements": None,
        }
        if path.exists():
            entry["sha256"] = _sha256_path(path)
            verbose = _codesign_verbose(path)
            ent = _codesign_entitlements(path)
            entry["codesign_verbose"] = verbose
            entry["codesign_kv"] = _parse_codesign_kv(verbose.get("stderr"))
            entry["codesign_entitlements"] = ent
        else:
            entry["missing"] = True
        out["binaries"][label] = entry
    return out


def _normalize_wrapper_results(wrapper_results: Mapping[str, Any], profile_key: str) -> Dict[str, Any]:
    profile = wrapper_results.get(profile_key) or {}
    out: Dict[str, Any] = {}
    for pid in probe_plan.probe_ids():
        wrapper_block = ((profile.get(pid) or {}).get("wrapper")) if isinstance(profile.get(pid), dict) else None
        if not isinstance(wrapper_block, dict):
            out[pid] = {"classification": "harness_error", "failure_kind": "MISSING_WRAPPER_RESULT"}
            continue
        status = wrapper_block.get("status")
        classification = "blocked" if status == "blocked" else "executed"
        normalized = {"probe_id": pid, "classification": classification, "exit_code": wrapper_block.get("exit_code")}
        stdout = wrapper_block.get("stdout") or ""
        stderr = wrapper_block.get("stderr") or ""

        if pid == "mach_lookup_cfprefsd_agent":
            obj, err = _parse_json_line(stdout)
            if err is not None:
                normalized.update({"parse_error": err, "decision": None})
            else:
                kr = obj.get("kr")
                normalized["kr"] = kr
                normalized["decision"] = "allow" if kr == 0 else "deny"
        elif pid in {"file_read", "file_write"}:
            obj, err = _parse_json_line(stdout)
            if err is not None:
                normalized.update({"parse_error": err, "decision": None})
            else:
                rc = obj.get("rc")
                err_no = obj.get("errno")
                normalized["rc"] = rc
                normalized["errno"] = err_no
                normalized["decision"] = "allow" if rc == 0 else "deny"
        elif pid in {"network_bind", "network_outbound_localhost"}:
            exit_code = wrapper_block.get("exit_code")
            normalized["decision"] = "allow" if exit_code == 0 else "deny"
            if stderr:
                normalized["stderr_hint"] = stderr.strip().splitlines()[-1]
        else:
            exit_code = wrapper_block.get("exit_code")
            normalized["decision"] = "allow" if exit_code == 0 else "deny"

        out[pid] = {"normalized": normalized, "raw": wrapper_block}
    return out


def _build_parity_summary(
    *,
    wrapper_results_path: Path,
    wrapper_profile_key: str,
    jail_results_path: Path,
    jail_variant: str,
) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "world_id": WORLD_ID,
        "baseline_wrapper": {
            "path": to_repo_relative(wrapper_results_path, REPO_ROOT),
            "profile_key": wrapper_profile_key,
        },
        "jail": {
            "path": to_repo_relative(jail_results_path, REPO_ROOT),
            "variant": jail_variant,
        },
        "match": [],
        "mismatch": [],
        "incomparable": [],
        "per_probe": {},
    }

    try:
        wrapper_results = json.loads(wrapper_results_path.read_text())
    except Exception as exc:
        summary["error"] = f"failed to read wrapper baseline: {type(exc).__name__}: {exc}"
        return summary

    try:
        jail_results = json.loads(jail_results_path.read_text())
    except Exception as exc:
        summary["error"] = f"failed to read jail results: {type(exc).__name__}: {exc}"
        return summary

    wrapper_norm = _normalize_wrapper_results(wrapper_results, wrapper_profile_key)
    jail_variants = (jail_results.get("variants") or {}) if isinstance(jail_results, dict) else {}
    jail_variant_block = jail_variants.get(jail_variant) if isinstance(jail_variants, dict) else None
    if not isinstance(jail_variant_block, dict):
        summary["error"] = f"missing jail variant: {jail_variant}"
        return summary

    for pid in probe_plan.probe_ids():
        w = wrapper_norm.get(pid) or {}
        j = jail_variant_block.get(pid) or {}
        w_norm = (w.get("normalized") if isinstance(w, dict) else None) or {}
        j_norm = (j.get("normalized") if isinstance(j, dict) else None) or {}

        record = {
            "wrapper": {"normalized": w_norm, "raw": w.get("raw") if isinstance(w, dict) else None},
            "jail": {"normalized": j_norm, "raw": j.get("raw") if isinstance(j, dict) else None},
        }
        summary["per_probe"][pid] = record

        w_class = w_norm.get("classification")
        j_class = j_norm.get("classification")
        if w_class != "executed" or j_class != "executed":
            summary["incomparable"].append(pid)
            continue
        if w_norm.get("decision") == j_norm.get("decision") and w_norm.get("decision") is not None:
            summary["match"].append(pid)
        else:
            summary["mismatch"].append(pid)

    return summary


def _stage_binaries(stage_root: Path) -> Dict[str, Any]:
    """
    Stage probe binaries under stage_root (invariant for jail runs).
    """

    mkdir_error = _mkdir(stage_root)
    staged: Dict[str, Any] = {"stage_root": str(stage_root), "mkdir_error": mkdir_error, "binaries": {}}
    if mkdir_error is not None:
        return staged

    for spec in probe_plan.staged_binary_specs(REPO_ROOT):
        dest = stage_root / spec.dest_name
        entry: Dict[str, Any] = {
            "id": spec.id,
            "src_path": to_repo_relative(spec.src_path, REPO_ROOT),
            "dest_path": str(dest),
            "copy_error": None,
            "chmod_error": None,
            "sha256_src": None,
            "sha256_dest": None,
        }
        try:
            entry["sha256_src"] = _sha256_path(spec.src_path)
            shutil.copy2(spec.src_path, dest)
            entry["sha256_dest"] = _sha256_path(dest)
            entry["chmod_error"] = _chmod_plus_x(dest)
        except Exception as exc:
            entry["copy_error"] = f"{type(exc).__name__}: {exc}"
            if dest.exists():
                entry["dest_exists"] = True
                try:
                    entry["sha256_dest"] = _sha256_path(dest)
                except Exception as sha_exc:
                    entry["sha256_dest_error"] = f"{type(sha_exc).__name__}: {sha_exc}"
        staged["binaries"][spec.id] = entry

    return staged


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def _with_log_stream_capture(
    *,
    artifact_path: Path,
    predicate: str,
    pre_s: float,
    post_s: float,
    action: Callable[[], Dict[str, Any]],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Best-effort capture of a short `log stream` window around `action`.

    This is used to discriminate "blocked at exec" by capturing sandboxd/amfid logs,
    rather than inferring from shell exit codes alone.
    """

    log_cmd = ["/usr/bin/log", "stream", "--style", "compact", "--predicate", predicate, "--info", "--debug"]

    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    start_ts = time.time()
    proc: Optional[subprocess.Popen] = None
    log_meta: Dict[str, Any] = {
        "command": log_cmd,
        "predicate": predicate,
        "path": to_repo_relative(artifact_path, REPO_ROOT),
        "start_ts": start_ts,
        "end_ts": None,
        "exit_code": None,
        "stderr": None,
        "error": None,
    }

    try:
        with artifact_path.open("w") as fh:
            proc = subprocess.Popen(log_cmd, stdout=fh, stderr=subprocess.PIPE, text=True)
            time.sleep(pre_s)
            result = action()
            time.sleep(post_s)
            proc.terminate()
            try:
                _, stderr_text = proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, stderr_text = proc.communicate(timeout=2)
            log_meta["stderr"] = stderr_text
            log_meta["exit_code"] = proc.returncode
            log_meta["end_ts"] = time.time()
            log_meta["size"] = _stat_path(artifact_path).get("size")
            return result, log_meta
    except Exception as exc:
        log_meta["error"] = f"{type(exc).__name__}: {exc}"
        # If logging fails, still run the action so we don't block the witness.
        result = action()
        log_meta["end_ts"] = time.time()
        return result, log_meta
    finally:
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass


def _capture_under_jail_with_logs(
    *,
    stage_root: Path,
    capture_root: Optional[Path] = None,
    attempt_id: str,
    command: List[str],
    log_label: str,
    timeout_s: float,
    predicate: str = LOG_STREAM_PREDICATE_SANDBOXD_AMFID,
    pre_s: float = 0.2,
    post_s: float = 1.5,
) -> Dict[str, Any]:
    log_path = OUT_DIR / f"jail_logs_{log_label}_{_deterministic_run_id()}.log"

    def run() -> Dict[str, Any]:
        return _capture_under_jail(
            stage_root=stage_root,
            capture_root=capture_root,
            attempt_id=attempt_id,
            command=command,
            timeout_s=timeout_s,
        )

    result, log_meta = _with_log_stream_capture(
        artifact_path=log_path,
        predicate=predicate,
        pre_s=pre_s,
        post_s=post_s,
        action=run,
    )
    if isinstance(result, dict):
        result["log_capture"] = log_meta
    return result


def _stage_discovery_matrix(*, stage_root: Path, capture_root: Optional[Path] = None, run_id: str) -> Dict[str, Any]:
    """
    Small, explicit discovery matrix: path × operation(stat/open/exec).

    This is a witness artifact that bounds what is runnable/readable under the jail
    on this host. It is not a promoted mapping.
    """

    file_probe_src = REPO_ROOT / "book" / "api" / "file_probe" / "file_probe"
    repo_open_target = REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "Report.md"

    roots: List[Tuple[str, Path]] = [
        ("repo_checkout", REPO_ROOT),
        ("tmp", Path("/tmp")),
        ("private_tmp", Path("/private/tmp")),
        ("stage_root", stage_root),
    ]

    matrix: Dict[str, Any] = {"run_id": run_id, "roots": {}}

    for key, root in roots:
        entry: Dict[str, Any] = {"root": str(root), "prep": {}, "ops": {}}

        if key == "repo_checkout":
            entry["exec_binary"] = str(file_probe_src)
            entry["exec_binary_repo"] = to_repo_relative(file_probe_src, REPO_ROOT)
            entry["open_target"] = str(repo_open_target)
            entry["open_target_repo"] = to_repo_relative(repo_open_target, REPO_ROOT)
        elif key == "stage_root":
            test_file = root / f"sbl_jail_discovery_{run_id}.txt"
            try:
                test_file.write_text("discovery\n")
            except Exception as exc:
                entry["prep"]["test_file_write_error"] = f"{type(exc).__name__}: {exc}"
            entry["exec_binary"] = str(root / "file_probe")
            entry["open_target"] = str(test_file)
        else:
            test_file = root / f"sbl_jail_discovery_{run_id}.txt"
            try:
                test_file.write_text("discovery\n")
            except Exception as exc:
                entry["prep"]["test_file_write_error"] = f"{type(exc).__name__}: {exc}"
            copied_probe = root / f"sbl_file_probe_{run_id}"
            try:
                shutil.copy2(file_probe_src, copied_probe)
                _chmod_plus_x(copied_probe)
                entry["prep"]["copied_file_probe_path"] = str(copied_probe)
                entry["prep"]["copied_file_probe_sha256"] = _sha256_path(copied_probe)
            except Exception as exc:
                entry["prep"]["copy_file_probe_error"] = f"{type(exc).__name__}: {exc}"
            entry["exec_binary"] = str(copied_probe)
            entry["open_target"] = str(test_file)

        entry["ops"]["stat"] = _capture_under_jail(
            stage_root=stage_root,
            capture_root=capture_root,
            attempt_id=f"discovery.{key}.stat",
            command=["/bin/ls", "-ld", str(root)],
        )
        entry["ops"]["open"] = _capture_under_jail(
            stage_root=stage_root,
            capture_root=capture_root,
            attempt_id=f"discovery.{key}.open",
            command=["/bin/cat", entry["open_target"]],
        )
        entry["ops"]["exec"] = _capture_under_jail(
            stage_root=stage_root,
            capture_root=capture_root,
            attempt_id=f"discovery.{key}.exec",
            # Exec-only: file_probe exits with usage when no args are provided.
            command=[entry["exec_binary"]],
        )

        matrix["roots"][key] = entry

    return matrix


def _exec_gate_matrix(
    *,
    stage_root: Path,
    capture_root: Optional[Path] = None,
    run_id: str,
    staged: Mapping[str, Path],
) -> Dict[str, Any]:
    """
    Tight discriminant matrix for exec gating under the jail.

    The goal is to answer one key question with evidence: does *any* non-in-place executable
    run under the jail? This lets us discriminate identity/signature gates vs
    location/writable-location gates.
    """

    doc: Dict[str, Any] = {"run_id": run_id, "prep": {}, "tests": {}, "summary": {}}

    relocated_true = stage_root / f"relocated_true_{run_id}"
    relocated_prep: Dict[str, Any] = {"src": "/usr/bin/true", "dest": str(relocated_true), "sha256_src": None}
    try:
        relocated_prep["sha256_src"] = _sha256_path(Path("/usr/bin/true"))
    except Exception as exc:
        relocated_prep["sha256_src_error"] = f"{type(exc).__name__}: {exc}"
    if relocated_true.exists():
        relocated_prep["existing_dest"] = True
        relocated_prep["copy_skipped"] = True
        try:
            relocated_prep["sha256_dest"] = _sha256_path(relocated_true)
        except Exception as sha_exc:
            relocated_prep["sha256_dest_error"] = f"{type(sha_exc).__name__}: {sha_exc}"
    else:
        try:
            shutil.copy2("/usr/bin/true", relocated_true)
            relocated_prep["sha256_dest"] = _sha256_path(relocated_true)
            relocated_prep["chmod_error"] = _chmod_plus_x(relocated_true)
        except Exception as exc:
            relocated_prep["copy_error"] = f"{type(exc).__name__}: {exc}"
    doc["prep"]["relocated_true"] = relocated_prep

    # System binary in place (baseline sanity): /usr/bin/true
    doc["tests"]["system_in_place_true"] = _capture_under_jail(
        stage_root=stage_root,
        capture_root=capture_root,
        attempt_id="gate.system_in_place_true",
        command=["/usr/bin/true"],
        timeout_s=6.0,
    )

    # System binary relocated into the container stage root.
    doc["tests"]["system_relocated_true"] = _capture_under_jail_with_logs(
        stage_root=stage_root,
        capture_root=capture_root,
        attempt_id="gate.system_relocated_true",
        command=[str(relocated_true)],
        log_label="exec_gate_relocated_true",
        timeout_s=6.0,
    )

    # Staged probe helpers (exec-only): run with missing args to avoid confounding I/O.
    doc["tests"]["staged_file_probe_usage"] = _capture_under_jail_with_logs(
        stage_root=stage_root,
        capture_root=capture_root,
        attempt_id="gate.staged_file_probe_usage",
        command=[str(staged["file_probe"])],
        log_label="exec_gate_file_probe_usage",
        timeout_s=6.0,
    )
    doc["tests"]["staged_mach_probe_usage"] = _capture_under_jail(
        stage_root=stage_root,
        capture_root=capture_root,
        attempt_id="gate.staged_mach_probe_usage",
        command=[str(staged["mach_probe"])],
        timeout_s=6.0,
    )

    # Trivial locally-signed / unsigned Mach-Os (these may also exercise network, but we only
    # care about "exec started" vs "blocked at exec" here).
    doc["tests"]["staged_entitlement_sample"] = _capture_under_jail(
        stage_root=stage_root,
        capture_root=capture_root,
        attempt_id="gate.staged_entitlement_sample",
        command=[str(staged["entitlement_sample"])],
        timeout_s=6.0,
    )
    doc["tests"]["staged_entitlement_sample_unsigned"] = _capture_under_jail(
        stage_root=stage_root,
        capture_root=capture_root,
        attempt_id="gate.staged_entitlement_sample_unsigned",
        command=[str(staged["entitlement_sample_unsigned"])],
        timeout_s=6.0,
    )

    def is_executed(key: str) -> bool:
        rec = doc["tests"].get(key)
        return isinstance(rec, dict) and rec.get("classification") == "executed"

    summary: Dict[str, Any] = {
        "system_in_place_executed": is_executed("system_in_place_true"),
        "system_relocated_executed": is_executed("system_relocated_true"),
        "staged_file_probe_executed": is_executed("staged_file_probe_usage"),
        "staged_mach_probe_executed": is_executed("staged_mach_probe_usage"),
        "staged_entitlement_sample_executed": is_executed("staged_entitlement_sample"),
        "staged_entitlement_sample_unsigned_executed": is_executed("staged_entitlement_sample_unsigned"),
    }

    summary["any_non_in_place_exec_executed"] = bool(
        summary["system_relocated_executed"]
        or summary["staged_file_probe_executed"]
        or summary["staged_mach_probe_executed"]
        or summary["staged_entitlement_sample_executed"]
        or summary["staged_entitlement_sample_unsigned_executed"]
    )
    summary["required_probe_helpers_executed"] = bool(summary["staged_file_probe_executed"] and summary["staged_mach_probe_executed"])

    failure_kind: Optional[str] = None
    relocated_prep = doc.get("prep", {}).get("relocated_true", {}) if isinstance(doc.get("prep"), dict) else {}
    relocated_available = bool(isinstance(relocated_prep, dict) and Path(str(relocated_prep.get("dest") or "")).exists())

    if not summary["required_probe_helpers_executed"]:
        if not relocated_available:
            # Without a relocated system-binary test we can't discriminate identity vs location.
            failure_kind = "EXEC_GATE_RELOCATED_SYSTEM_TEST_UNAVAILABLE"
        elif summary["system_relocated_executed"]:
            failure_kind = "EXEC_GATE_STAGED_PROBES_DENIED"
        else:
            failure_kind = "EXEC_GATE_LOCATION_OR_WRITABLE_DENIED"

    summary["proceed"] = failure_kind is None
    summary["failure_kind"] = failure_kind
    doc["summary"] = summary
    return doc


def main() -> int:
    run_id = _deterministic_run_id()
    session_id = f"{int(time.time())}-{os.getpid()}"
    meta = {
        "world_id": WORLD_ID,
        "run_id": run_id,
        "session_id": session_id,
        "entitlement_jail": {
            "path": to_repo_relative(ENTITLEMENT_JAIL, REPO_ROOT),
            "sha256": _sha256_path(ENTITLEMENT_JAIL) if ENTITLEMENT_JAIL.exists() else None,
        },
    }

    # Bootstrap env probe: try a few candidate stage roots and record what happens.
    candidate_stage_roots: List[Dict[str, str]] = [
        {"kind": "tmp", "path": "/tmp/sandbox-lore-entitlement-jail"},
        {"kind": "private_tmp", "path": "/private/tmp/sandbox-lore-entitlement-jail"},
        {"kind": "home", "path": str(Path.home() / "jail_stage" / "entitlement-diff" / f"bootstrap-{run_id}")},
        {
            "kind": "speculative_container",
            "path": str(
                Path.home()
                / "Library"
                / "Containers"
                / "com.yourteam.entitlement-jail"
                / "Data"
                / "jail_stage"
                / "entitlement-diff"
                / f"bootstrap-{run_id}"
            ),
        },
    ]

    env_probe_attempts: List[Dict[str, Any]] = []
    observed_env: Dict[str, str] = {}
    observed_home: Optional[str] = None
    observed_tmpdir: Optional[str] = None
    observed_pwd: Optional[str] = None
    chosen_bootstrap_stage: Optional[str] = None

    bootstrap_timeout_s = 8.0
    for cand in candidate_stage_roots:
        stage_root = Path(cand["path"])
        capture_root = stage_root / "jail_out" / session_id
        mkdir_error = _mkdir(stage_root)
        attempt: Dict[str, Any] = {"candidate": cand, "mkdir_error": mkdir_error, "probes": {}}
        if mkdir_error is not None:
            env_probe_attempts.append(attempt)
            continue

        env_res = _capture_under_jail(
            stage_root=stage_root,
            capture_root=capture_root,
            attempt_id="env.env",
            command=["/usr/bin/env"],
            timeout_s=bootstrap_timeout_s,
        )
        attempt["probes"]["env"] = env_res
        if env_res.get("classification") != "executed":
            attempt["probes"]["id"] = {"classification": "blocked", "failure_kind": "SKIPPED_ENV_FAILED"}
            attempt["probes"]["pwd"] = {"classification": "blocked", "failure_kind": "SKIPPED_ENV_FAILED"}
            env_probe_attempts.append(attempt)
            continue

        id_res = _capture_under_jail(
            stage_root=stage_root,
            capture_root=capture_root,
            attempt_id="env.id",
            command=["/usr/bin/id", "-a"],
            timeout_s=bootstrap_timeout_s,
        )
        pwd_res = _capture_under_jail(
            stage_root=stage_root,
            capture_root=capture_root,
            attempt_id="env.pwd",
            command=["/bin/pwd"],
            timeout_s=bootstrap_timeout_s,
        )
        attempt["probes"].update({"id": id_res, "pwd": pwd_res})
        env_probe_attempts.append(attempt)

        env_stdout = (((env_res.get("capture") or {}) if isinstance(env_res.get("capture"), dict) else {}).get("stdout")) or ""
        observed_env = _parse_env_block(env_stdout)
        observed_home = observed_env.get("HOME")
        observed_tmpdir = observed_env.get("TMPDIR")
        if pwd_res.get("classification") == "executed":
            observed_pwd = (
                (((pwd_res.get("capture") or {}) if isinstance(pwd_res.get("capture"), dict) else {}).get("stdout"))
                or ""
            ).strip()
        chosen_bootstrap_stage = cand["path"]
        break

    env_probe_doc: Dict[str, Any] = {
        "meta": meta,
        "env_probe_attempts": env_probe_attempts,
        "observed": {
            "HOME": observed_home,
            "TMPDIR": observed_tmpdir,
            "PWD": observed_pwd,
        },
        "observed_env": observed_env,
    }

    # If we got a HOME, move to the invariant stage root under that HOME.
    stage_root: Optional[Path] = None
    if observed_home:
        stage_root = Path(observed_home) / "jail_stage" / "entitlement-diff" / run_id
        env_probe_doc["chosen_bootstrap_stage_root"] = chosen_bootstrap_stage
        env_probe_doc["stage_root"] = str(stage_root)

    if stage_root is None:
        _write_json(JAIL_ENV_PROBE_PATH, env_probe_doc)
        print(f"[+] wrote {to_repo_relative(JAIL_ENV_PROBE_PATH, REPO_ROOT)}")
        # Cannot proceed without a writable stage root anchored at observed HOME.
        runtime_doc = {
            "meta": meta,
            "status": "blocked",
            "failure_kind": "NO_OBSERVED_HOME",
            "env_probe": to_repo_relative(JAIL_ENV_PROBE_PATH, REPO_ROOT),
            "variants": {},
        }
        _write_json(JAIL_RUNTIME_RESULTS_PATH, runtime_doc)
        _write_json(JAIL_ENTITLEMENTS_PATH, {"meta": meta, "status": "blocked", "failure_kind": "NO_OBSERVED_HOME"})
        _write_json(
            JAIL_PARITY_SUMMARY_PATH,
            {"meta": meta, "status": "blocked", "failure_kind": "NO_OBSERVED_HOME"},
        )
        print(f"[+] wrote {to_repo_relative(JAIL_RUNTIME_RESULTS_PATH, REPO_ROOT)}")
        print(f"[+] wrote {to_repo_relative(JAIL_ENTITLEMENTS_PATH, REPO_ROOT)}")
        print(f"[+] wrote {to_repo_relative(JAIL_PARITY_SUMMARY_PATH, REPO_ROOT)}")
        return 2

    stage_info = _stage_binaries(stage_root)
    staged = probe_plan.staged_destinations(stage_root, REPO_ROOT)
    capture_root = stage_root / "jail_out" / session_id
    env_probe_doc["exec_gate"] = _exec_gate_matrix(stage_root=stage_root, capture_root=capture_root, run_id=run_id, staged=staged)
    env_probe_doc["stage_discovery"] = _stage_discovery_matrix(stage_root=stage_root, capture_root=capture_root, run_id=run_id)
    _write_json(JAIL_ENV_PROBE_PATH, env_probe_doc)
    print(f"[+] wrote {to_repo_relative(JAIL_ENV_PROBE_PATH, REPO_ROOT)}")

    exec_gate = env_probe_doc.get("exec_gate") if isinstance(env_probe_doc, dict) else None
    exec_gate_summary = (exec_gate.get("summary") if isinstance(exec_gate, dict) else None) or {}
    exec_gate_failure = exec_gate_summary.get("failure_kind") if isinstance(exec_gate_summary, dict) else None
    if exec_gate_failure:
        runtime_doc = {
            "meta": meta,
            "status": "blocked",
            "failure_kind": exec_gate_failure,
            "env_probe": to_repo_relative(JAIL_ENV_PROBE_PATH, REPO_ROOT),
            "stage_root": str(stage_root),
            "stage_info": stage_info,
            "variants": {},
        }
        _write_json(JAIL_RUNTIME_RESULTS_PATH, runtime_doc)
        print(f"[+] wrote {to_repo_relative(JAIL_RUNTIME_RESULTS_PATH, REPO_ROOT)}")

        ent_doc = _extract_parent_and_child_entitlements(stage_root)
        ent_doc["meta"] = meta
        _write_json(JAIL_ENTITLEMENTS_PATH, ent_doc)
        print(f"[+] wrote {to_repo_relative(JAIL_ENTITLEMENTS_PATH, REPO_ROOT)}")

        _write_json(
            JAIL_PARITY_SUMMARY_PATH,
            {"meta": meta, "status": "blocked", "failure_kind": exec_gate_failure},
        )
        print(f"[+] wrote {to_repo_relative(JAIL_PARITY_SUMMARY_PATH, REPO_ROOT)}")
        return 2

    container_dir = stage_root / "container"
    container_mkdir_error = _mkdir(container_dir)
    target_path = container_dir / "runtime.txt"
    target_write_error: Optional[str] = None
    if container_mkdir_error is None:
        try:
            target_path.write_text("entitlement-diff jail runtime file\n")
        except Exception as exc:
            target_write_error = f"{type(exc).__name__}: {exc}"

    # Smoke: prove we can exec a real probe from stage_root.
    smoke_path = stage_root / "smoke.txt"
    smoke_write_error: Optional[str] = None
    try:
        smoke_path.write_text("smoke\n")
    except Exception as exc:
        smoke_write_error = f"{type(exc).__name__}: {exc}"

    smoke_cmd = [str(staged["file_probe"]), "read", str(smoke_path)]
    smoke = _capture_under_jail(stage_root=stage_root, capture_root=capture_root, attempt_id="smoke.file_probe_read", command=smoke_cmd)
    smoke_norm = _normalize_probe_outcome("file_read", smoke) if smoke.get("classification") == "executed" else None
    smoke_record = {"raw": smoke, "normalized": smoke_norm, "smoke_write_error": smoke_write_error}

    variants: Dict[str, Dict[str, Any]] = {}
    variant_map = {
        "signed": "entitlement_sample",
        "no_entitlements": "entitlement_sample_unsigned",
    }

    if smoke.get("classification") != "executed":
        # Record all probes as blocked by prerequisite failure.
        for variant in variant_map:
            variants[variant] = {
                pid: {
                    "raw": {"classification": "blocked", "failure_kind": "DEPENDENCY_EXEC_SMOKE_FAILED"},
                    "normalized": {"probe_id": pid, "classification": "blocked", "decision": None},
                }
                for pid in probe_plan.probe_ids()
            }
    else:
        for variant, bind_id in variant_map.items():
            tests = probe_plan.build_probe_matrix(stage_dir=stage_root, container_dir=container_dir, network_bind_binary_id=bind_id, repo_root=REPO_ROOT)
            variant_results: Dict[str, Any] = {}
            for test in tests:
                pid = str(test["id"])
                cmd = list(test["command"])  # type: ignore[list-item]
                raw = _capture_under_jail(stage_root=stage_root, capture_root=capture_root, attempt_id=f"{variant}.{pid}", command=cmd)
                norm = _normalize_probe_outcome(pid, raw) if raw.get("classification") == "executed" else {"probe_id": pid, "classification": raw.get("classification"), "decision": None}
                variant_results[pid] = {"raw": raw, "normalized": norm}
            variants[variant] = variant_results

    runtime_doc = {
        "meta": meta,
        "env_probe": to_repo_relative(JAIL_ENV_PROBE_PATH, REPO_ROOT),
        "stage_root": str(stage_root),
        "stage_info": stage_info,
        "container_dir": str(container_dir),
        "container_mkdir_error": container_mkdir_error,
        "file_probe_target": str(target_path),
        "file_probe_target_write_error": target_write_error,
        "smoke": smoke_record,
        "variants": variants,
    }
    _write_json(JAIL_RUNTIME_RESULTS_PATH, runtime_doc)
    print(f"[+] wrote {to_repo_relative(JAIL_RUNTIME_RESULTS_PATH, REPO_ROOT)}")

    ent_doc = _extract_parent_and_child_entitlements(stage_root)
    ent_doc["meta"] = meta
    _write_json(JAIL_ENTITLEMENTS_PATH, ent_doc)
    print(f"[+] wrote {to_repo_relative(JAIL_ENTITLEMENTS_PATH, REPO_ROOT)}")

    parity = _build_parity_summary(
        wrapper_results_path=WRAPPER_RESULTS_PATH,
        wrapper_profile_key="baseline",
        jail_results_path=JAIL_RUNTIME_RESULTS_PATH,
        jail_variant="signed",
    )
    parity["meta"] = meta
    _write_json(JAIL_PARITY_SUMMARY_PATH, parity)
    print(f"[+] wrote {to_repo_relative(JAIL_PARITY_SUMMARY_PATH, REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
