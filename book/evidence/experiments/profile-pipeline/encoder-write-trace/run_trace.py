#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import platform
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

def _find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    for candidate in [cur] + list(cur.parents):
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError("Unable to locate repo root")


REPO_ROOT = _find_repo_root(Path(__file__))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import ensure_absolute, find_repo_root, relativize_command, to_repo_relative  # type: ignore
from book.api.profile.identity import baseline_world_id  # type: ignore

TARGET_SYMBOL = "_sb_mutable_buffer_write"
SECONDARY_SYMBOL = "_sb_mutable_buffer_make_immutable"
DEFAULT_BIND_IMAGE = Path("book/integration/carton/bundle/relationships/mappings/dyld-libs/usr/lib/libsandbox.1.dylib")
RETRY_SIGNALS = {int(signal.SIGSEGV), int(signal.SIGTRAP)}
DEFAULT_RETRIES = 1

COMPILE_SNIPPET = r"""
import ctypes
import hashlib
import json
import os
import sys
from pathlib import Path

DEFAULT_SANDBOX_PATH = "/usr/lib/libsandbox.1.dylib"


def _find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    for candidate in [cur] + list(cur.parents):
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError("Unable to locate repo root")


def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _write_json(payload: object) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")


def _parse_params(raw):
    if not raw:
        return None
    value = json.loads(raw)
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    raise ValueError("params must be a JSON object mapping string keys to string values")


def _emit_error(
    *,
    input_path: Path,
    out_blob: Path,
    mode: str,
    params,
    error_stage: str,
    error: str,
    repo_root: Path,
) -> int:
    payload = {
        "status": "error",
        "input": to_repo_relative(input_path, repo_root),
        "out_blob": to_repo_relative(out_blob, repo_root),
        "mode": mode,
        "params": params,
        "error_stage": error_stage,
        "error": error,
    }
    _write_json(payload)
    if out_blob.exists():
        out_blob.unlink()
    return 2


repo_root = os.environ.get("SBPL_REPO_ROOT")
repo_root_path = Path(repo_root).resolve() if repo_root else _find_repo_root(Path.cwd())
if str(repo_root_path) not in sys.path:
    sys.path.insert(0, str(repo_root_path))

from book.api.path_utils import ensure_absolute, to_repo_relative  # type: ignore
from book.api.profile import compile as compile_mod  # type: ignore
from book.api.profile.compile import libsandbox  # type: ignore


def main() -> int:
    input_raw = os.environ.get("SBPL_COMPILE_INPUT")
    out_raw = os.environ.get("SBPL_COMPILE_OUT_BLOB")
    mode = os.environ.get("SBPL_COMPILE_MODE", "file")
    params_raw = os.environ.get("SBPL_COMPILE_PARAMS")
    if not input_raw or not out_raw:
        _write_json(
            {
                "status": "error",
                "error_stage": "config",
                "error": "SBPL_COMPILE_INPUT and SBPL_COMPILE_OUT_BLOB are required",
            }
        )
        return 2

    input_path = ensure_absolute(Path(input_raw), repo_root_path)
    out_blob = ensure_absolute(Path(out_raw), repo_root_path)
    try:
        params = _parse_params(params_raw)
    except Exception as exc:
        return _emit_error(
            input_path=input_path,
            out_blob=out_blob,
            mode=mode,
            params=None,
            error_stage="parse_params",
            error=str(exc),
            repo_root=repo_root_path,
        )

    sandbox_path = os.environ.get("SBPL_SANDBOX_PATH")
    lib = None
    if sandbox_path and sandbox_path != DEFAULT_SANDBOX_PATH:
        sandbox_abs = ensure_absolute(Path(sandbox_path), repo_root_path)
        if not sandbox_abs.exists():
            return _emit_error(
                input_path=input_path,
                out_blob=out_blob,
                mode=mode,
                params=params,
                error_stage="sandbox_path",
                error=f"SBPL_SANDBOX_PATH does not exist: {sandbox_path}",
                repo_root=repo_root_path,
            )
        try:
            lib = ctypes.CDLL(str(sandbox_abs))
        except OSError as exc:
            return _emit_error(
                input_path=input_path,
                out_blob=out_blob,
                mode=mode,
                params=params,
                error_stage="load_libsandbox",
                error=f"failed to load libsandbox from {sandbox_path}: {exc}",
                repo_root=repo_root_path,
            )
    else:
        try:
            lib = libsandbox.load_libsandbox()
        except Exception as exc:
            return _emit_error(
                input_path=input_path,
                out_blob=out_blob,
                mode=mode,
                params=params,
                error_stage="load_libsandbox",
                error=str(exc),
                repo_root=repo_root_path,
            )

    try:
        if mode == "string":
            try:
                sbpl_text = input_path.read_text()
            except Exception as exc:
                return _emit_error(
                    input_path=input_path,
                    out_blob=out_blob,
                    mode=mode,
                    params=params,
                    error_stage="read_input",
                    error=str(exc),
                    repo_root=repo_root_path,
                )
            result = compile_mod.compile_sbpl_string(sbpl_text, lib=lib, params=params)
            out_blob.parent.mkdir(parents=True, exist_ok=True)
            out_blob.write_bytes(result.blob)
        else:
            result = compile_mod.compile_sbpl_file(input_path, out_blob, lib=lib, params=params)
    except Exception as exc:
        return _emit_error(
            input_path=input_path,
            out_blob=out_blob,
            mode=mode,
            params=params,
            error_stage="compile",
            error=str(exc),
            repo_root=repo_root_path,
        )

    payload = {
        "status": "ok",
        "input": to_repo_relative(input_path, repo_root_path),
        "out_blob": to_repo_relative(out_blob, repo_root_path),
        "mode": mode,
        "params": params,
        "length": result.length,
        "profile_type": result.profile_type,
        "blob_sha256": _sha256_bytes(result.blob),
    }
    _write_json(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"""

def _load_inputs(path: Path) -> Mapping[str, Any]:
    raw = json.loads(path.read_text())
    if not isinstance(raw, Mapping):
        raise ValueError("inputs.json must be a JSON object")
    return raw


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _run_tool(cmd: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True)


def _trim_text(value: str, limit: int = 4096) -> str:
    trimmed = value.strip()
    if len(trimmed) <= limit:
        return trimmed
    return trimmed[:limit] + "...(truncated)"


def _signal_from_returncode(returncode: int) -> Optional[int]:
    if returncode < 0:
        return -returncode
    return None


def _signal_name(signal_number: Optional[int]) -> Optional[str]:
    if signal_number is None:
        return None
    try:
        return signal.Signals(signal_number).name
    except ValueError:
        return f"SIG{signal_number}"


def _normalize_params(raw: Any) -> Optional[Dict[str, str]]:
    if raw is None:
        return None
    if isinstance(raw, Mapping):
        return {str(k): str(v) for k, v in raw.items()}
    raise ValueError("compile params must be a JSON object mapping string keys to string values")


def _parse_nm_scope(output: str, symbol: str) -> Dict[str, Any]:
    scope = None
    line_match = None
    address = None
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.endswith(f" {symbol}"):
            continue
        line_match = stripped
        parts = stripped.split()
        if parts:
            addr_text = parts[0]
            if re.fullmatch(r"0x[0-9a-fA-F]+", addr_text) or re.fullmatch(r"[0-9a-fA-F]+", addr_text):
                try:
                    addr_val = int(addr_text, 16)
                    address = f"0x{addr_val:016x}"
                except Exception:
                    address = None
        if " non-external " in stripped:
            scope = "non-external"
        elif " external " in stripped:
            scope = "external"
        elif " undefined " in stripped:
            scope = "undefined"
        else:
            scope = "unknown"
        break
    return {
        "scope": scope or "missing",
        "line": line_match,
        "address": address,
    }


def _read_dwarfdump_uuids(path: Path, repo_root: Path) -> Dict[str, Any]:
    result = _run_tool(["xcrun", "dwarfdump", "--uuid", str(path)])
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if result.returncode != 0:
        return {
            "status": "error",
            "path": to_repo_relative(path, repo_root),
            "error": stderr or "dwarfdump failed",
            "entries": [],
        }
    entries: List[Dict[str, str]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("UUID:"):
            continue
        match = re.match(r"UUID: ([0-9A-Fa-f-]+) \(([^)]+)\) (.+)", line)
        if not match:
            continue
        raw_path = match.group(3)
        if Path(raw_path).is_absolute():
            try:
                entry_path = to_repo_relative(Path(raw_path), repo_root)
            except Exception:
                entry_path = raw_path
        else:
            entry_path = raw_path
        entries.append(
            {
                "uuid": match.group(1).lower(),
                "arch": match.group(2),
                "path": entry_path,
            }
        )
    return {
        "status": "ok",
        "path": to_repo_relative(path, repo_root),
        "entries": entries,
    }


def _select_uuid(entries: List[Dict[str, str]], arch: str) -> Dict[str, Optional[str]]:
    if not entries:
        return {"uuid": None, "arch": None}
    for entry in entries:
        if entry.get("arch") == arch:
            return {"uuid": entry.get("uuid"), "arch": arch}
    if arch == "arm64":
        for entry in entries:
            if entry.get("arch") == "arm64e":
                return {"uuid": entry.get("uuid"), "arch": "arm64e"}
    if len(entries) == 1:
        entry = entries[0]
        return {"uuid": entry.get("uuid"), "arch": entry.get("arch")}
    return {"uuid": None, "arch": None}


def _parse_otool_indirect_sections(output: str, symbol: str) -> Dict[str, Any]:
    current_section: Optional[str] = None
    sections: List[str] = []
    header_re = re.compile(r"^Indirect symbols for \\(([^,]+),([^\\)]+)\\)")
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        header = header_re.match(stripped)
        if header:
            seg = header.group(1).strip()
            sect = header.group(2).strip()
            current_section = f"{seg},{sect}"
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        if not parts[0].startswith("0x"):
            continue
        name = parts[2]
        if name == symbol and current_section:
            sections.append(current_section)
    return {
        "sections": sorted(set(sections)),
    }


def _bind_kinds_from_sections(sections: List[str]) -> List[str]:
    kinds: List[str] = []
    for section in sections:
        seg, _, sect = section.partition(",")
        sect = sect.strip()
        if sect in {"__la_symbol_ptr", "__auth_ptr", "__auth_ptr2"}:
            kinds.append("lazy_bind")
        elif sect in {"__nl_symbol_ptr", "__got", "__auth_got"}:
            kinds.append("bind")
        elif "stubs" in sect:
            kinds.append("stub")
        else:
            kinds.append("unknown")
    return sorted(set(kinds))


def _callsite_reachability(sections: List[str]) -> str:
    if not sections:
        return "internal_direct"
    for section in sections:
        _, _, sect = section.partition(",")
        if "stubs" in sect:
            return "imported_through_stub"
    return "exported_bound"


def _dyld_info_symbol_presence(path: Path, symbol: str, flag: str) -> Dict[str, Any]:
    result = _run_tool(["xcrun", "dyld_info", flag, str(path)])
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if result.returncode != 0 or stdout.startswith("dyld_info:"):
        return {
            "status": "error",
            "path": str(path),
            "error": stdout or stderr or "dyld_info failed",
            "present": None,
        }
    present = bool(re.search(rf"\\b{re.escape(symbol)}\\b", stdout))
    return {
        "status": "ok",
        "path": str(path),
        "present": present,
    }


def _dyld_info_bundle(
    image_path: Path,
    symbol: str,
    *,
    fallback_path: Optional[Path],
) -> Dict[str, Any]:
    requested = {
        "exports": _dyld_info_symbol_presence(image_path, symbol, "-exports"),
        "imports": _dyld_info_symbol_presence(image_path, symbol, "-imports"),
    }
    out: Dict[str, Any] = {
        "role": "convenience",
        "requested_path": str(image_path),
        "fallback_path": str(fallback_path) if fallback_path else None,
        "requested": requested,
        "used_fallback": False,
    }
    if fallback_path and fallback_path != image_path:
        if requested["exports"].get("status") == "error" or requested["imports"].get("status") == "error":
            if fallback_path.exists():
                out["fallback"] = {
                    "exports": _dyld_info_symbol_presence(fallback_path, symbol, "-exports"),
                    "imports": _dyld_info_symbol_presence(fallback_path, symbol, "-imports"),
                }
                out["used_fallback"] = True
            else:
                out["fallback_error"] = f"dyld_info fallback missing: {fallback_path}"
    return out


def _analyze_bind_tables(
    repo_root: Path,
    image_path: Path,
    symbol: str,
    *,
    dyld_fallback: Optional[Path],
    uuid_host_path: Optional[Path],
) -> Dict[str, Any]:
    analysis: Dict[str, Any] = {
        "symbol": symbol,
        "caller_image": to_repo_relative(image_path, repo_root),
    }
    if not image_path.exists():
        analysis["status"] = "missing"
        analysis["error"] = "caller image not found"
        analysis["caller_has_bind_record"] = None
        analysis["bind_kinds"] = []
        analysis["callsite_reachability"] = "unknown"
        return analysis

    nm_result = _run_tool(["nm", "-m", str(image_path)])
    if nm_result.returncode == 0:
        analysis["nm"] = _parse_nm_scope(nm_result.stdout, symbol)
        analysis["nm_secondary"] = _parse_nm_scope(nm_result.stdout, SECONDARY_SYMBOL)
    else:
        analysis["nm"] = {"scope": "unavailable", "error": nm_result.stderr.strip() or "nm failed"}
        analysis["nm_secondary"] = {"scope": "unavailable", "error": nm_result.stderr.strip() or "nm failed"}

    otool_result = _run_tool(["otool", "-Iv", str(image_path)])
    if otool_result.returncode == 0:
        indirect = _parse_otool_indirect_sections(otool_result.stdout, symbol)
        analysis["indirect"] = indirect
        sections = indirect.get("sections", [])
        analysis["caller_has_bind_record"] = bool(sections)
        analysis["bind_kinds"] = _bind_kinds_from_sections(sections)
        analysis["callsite_reachability"] = _callsite_reachability(sections)
        analysis["bind_kinds_source"] = "otool_indirect"
    else:
        analysis["indirect"] = {"sections": []}
        analysis["caller_has_bind_record"] = None
        analysis["bind_kinds"] = []
        analysis["callsite_reachability"] = "unknown"
        analysis["bind_kinds_source"] = "unavailable"
        analysis["bind_error"] = otool_result.stderr.strip() or "otool failed"

    dyld_bundle = _dyld_info_bundle(image_path, symbol, fallback_path=dyld_fallback)
    dyld_bundle["requested_path"] = to_repo_relative(Path(dyld_bundle["requested_path"]), repo_root)
    if dyld_bundle.get("fallback_path"):
        dyld_bundle["fallback_path"] = to_repo_relative(Path(dyld_bundle["fallback_path"]), repo_root)
    for scope in ("requested", "fallback"):
        scope_data = dyld_bundle.get(scope)
        if not isinstance(scope_data, Mapping):
            continue
        for kind in ("exports", "imports"):
            entry = scope_data.get(kind)
            if isinstance(entry, Mapping) and entry.get("path"):
                scope_data[kind] = dict(entry)
                scope_data[kind]["path"] = to_repo_relative(Path(entry["path"]), repo_root)
    analysis["dyld_info"] = dyld_bundle

    arch = platform.machine()
    extracted_uuid = _read_dwarfdump_uuids(image_path, repo_root)
    host_uuid = _read_dwarfdump_uuids(uuid_host_path, repo_root) if uuid_host_path else {
        "status": "missing",
        "path": None,
        "entries": [],
    }
    extracted_uuid["path"] = to_repo_relative(Path(extracted_uuid["path"]), repo_root)
    if host_uuid.get("path"):
        host_uuid["path"] = to_repo_relative(Path(host_uuid["path"]), repo_root)
    extracted_sel = _select_uuid(extracted_uuid.get("entries", []), arch)
    host_sel = _select_uuid(host_uuid.get("entries", []), arch)
    uuid_match = None
    if extracted_sel.get("uuid") and host_sel.get("uuid"):
        uuid_match = extracted_sel["uuid"] == host_sel["uuid"]
    analysis["uuid"] = {
        "arch_requested": arch,
        "extracted": extracted_uuid,
        "host": host_uuid,
        "extracted_selected": extracted_sel,
        "host_selected": host_sel,
        "match": uuid_match,
    }

    return analysis


def _augment_triage(
    triage_path: Path,
    bind_analysis: Mapping[str, Any],
    trace_records: int,
    *,
    mode: str,
    require_hits: bool,
    compile_info: Optional[Mapping[str, Any]] = None,
    stats: Optional[Mapping[str, Any]] = None,
) -> None:
    payload: Dict[str, Any] = {}
    if triage_path.exists():
        try:
            payload = json.loads(triage_path.read_text())
        except Exception:
            payload = {}
    hook_status = payload.get("hook_status")
    hook_error = payload.get("hook_error")
    payload["bind_analysis"] = dict(bind_analysis)
    payload["write_records"] = trace_records
    payload["hook_hit_count"] = trace_records
    compile_status = None
    if compile_info:
        payload["compile"] = {
            "status": compile_info.get("status"),
            "attempts": compile_info.get("attempts"),
            "retries_used": compile_info.get("retries_used"),
            "returncode": compile_info.get("returncode"),
            "signal": compile_info.get("signal"),
            "error": compile_info.get("error"),
        }
        compile_status = payload["compile"].get("status")
    if stats:
        payload["hw_breakpoint_stats"] = dict(stats)
    if bind_analysis.get("caller_has_bind_record") is None:
        payload["dyld_reachability"] = None
    else:
        payload["dyld_reachability"] = bool(bind_analysis.get("caller_has_bind_record"))
    if compile_status and compile_status != "ok":
        payload["reachability_validation"] = "compile_failed"
    elif mode != "triage":
        if trace_records > 0:
            payload["reachability_validation"] = "ok"
        elif hook_status == "ok":
            payload["reachability_validation"] = "no_hits"
        elif hook_status == "failed":
            payload["reachability_validation"] = "hook_failed"
        elif hook_status in ("skipped", "skipped_immutable"):
            payload["reachability_validation"] = "hook_skipped"
        else:
            payload["reachability_validation"] = "no_hits"
    _write_json(triage_path, payload)
    if compile_status and compile_status != "ok":
        return
    if mode != "triage" and require_hits and trace_records == 0:
        if hook_status == "ok":
            raise RuntimeError("hook applied but no write records observed; callsite likely unreachable")
        if hook_status == "failed" and isinstance(hook_error, str):
            if "mprotect failed" in hook_error:
                return
            raise RuntimeError(f"hook failed before execution: {hook_error}")
        if hook_status in ("skipped", "skipped_immutable") and isinstance(hook_error, str):
            raise RuntimeError(f"hook skipped: {hook_error}")
        raise RuntimeError("hook did not run and no write records observed")


def _run_compile(
    repo_root: Path,
    interposer: Path,
    sbpl_path: Path,
    trace_path: Path,
    stats_path: Path,
    out_blob: Path,
    *,
    compile_mode: str,
    compile_params: Optional[Dict[str, str]],
    mode: str,
    write_addr: Optional[str],
    write_unslid: Optional[str],
    write_uuid: Optional[str],
    write_offset: Optional[str],
    immutable_unslid: Optional[str],
    sandbox_path: Optional[str],
    dyld_shared_region: Optional[str],
    triage_path: Path,
    retries: int,
) -> Dict[str, Any]:
    env = dict(os.environ)
    env["DYLD_INSERT_LIBRARIES"] = str(interposer)
    env["SBPL_TRACE_OUT"] = str(trace_path)
    env["SBPL_TRACE_INPUT"] = to_repo_relative(sbpl_path, repo_root)
    env["SBPL_TRACE_MODE"] = mode
    env["SBPL_TRACE_TRIAGE_OUT"] = str(triage_path)
    env["SBPL_TRACE_STATS_OUT"] = str(stats_path)
    env["SBPL_REPO_ROOT"] = str(repo_root)
    env["SBPL_COMPILE_INPUT"] = str(sbpl_path)
    env["SBPL_COMPILE_OUT_BLOB"] = str(out_blob)
    env["SBPL_COMPILE_MODE"] = compile_mode
    if compile_params is not None:
        env["SBPL_COMPILE_PARAMS"] = json.dumps(compile_params, sort_keys=True)
    else:
        env.pop("SBPL_COMPILE_PARAMS", None)
    if write_addr:
        env["SBPL_WRITE_ADDR"] = write_addr
    if write_unslid:
        env["SBPL_WRITE_UNSLID"] = write_unslid
    if immutable_unslid:
        env["SBPL_WRITE_IMMUTABLE_UNSLID"] = immutable_unslid
    if write_uuid:
        env["SBPL_WRITE_UUID_EXPECTED"] = write_uuid
    if write_offset:
        env["SBPL_WRITE_OFFSET"] = write_offset
    if sandbox_path:
        env["SBPL_SANDBOX_PATH"] = sandbox_path
    if dyld_shared_region:
        env["DYLD_SHARED_REGION"] = dyld_shared_region

    env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [sys.executable, "-c", COMPILE_SNIPPET]
    attempts_log: List[Dict[str, Any]] = []
    attempts = 0
    retry_limit = max(0, retries)
    while True:
        attempts += 1
        if attempts > 1:
            for path in (trace_path, triage_path, stats_path, out_blob):
                if path.exists():
                    path.unlink()
        result = subprocess.run(cmd, env=env, cwd=repo_root, capture_output=True, text=True)
        returncode = result.returncode
        signal_number = _signal_from_returncode(returncode)
        signal_name = _signal_name(signal_number)
        attempt_entry: Dict[str, Any] = {
            "attempt": attempts,
            "returncode": returncode,
            "signal": signal_name,
        }
        stderr = _trim_text(result.stderr or "")
        if stderr:
            attempt_entry["stderr"] = stderr
        stdout = result.stdout.strip()
        parsed = None
        parsed_error = None
        parsed_status = None
        if stdout:
            try:
                parsed = json.loads(stdout)
                if isinstance(parsed, Mapping):
                    parsed_status = parsed.get("status")
            except json.JSONDecodeError as exc:
                parsed_error = f"compile output JSON parse failed: {exc}"
                attempt_entry["stdout"] = _trim_text(result.stdout or "")
        if returncode == 0 and parsed_status == "error":
            attempt_entry["error"] = parsed.get("error") if isinstance(parsed, Mapping) else "compile returned error status"
            if parsed is not None:
                attempt_entry["output"] = parsed
            attempts_log.append(attempt_entry)
            break
        if returncode == 0:
            if not stdout:
                attempt_entry["error"] = "compile script produced no JSON output"
                attempts_log.append(attempt_entry)
                break
            if parsed_error:
                attempt_entry["error"] = parsed_error
                attempts_log.append(attempt_entry)
                break
            payload = {
                "status": "ok",
                "attempts": attempts,
                "retries_used": attempts - 1,
                "returncode": returncode,
                "signal": signal_name,
                "output": parsed,
            }
            if attempts_log:
                payload["attempts_log"] = attempts_log
            return payload
        detail = f": {stderr}" if stderr else ""
        if parsed_status == "error" and isinstance(parsed, Mapping):
            attempt_entry["error"] = parsed.get("error") or parsed.get("error_stage") or "compile reported error"
            attempt_entry["output"] = parsed
        elif parsed_error:
            attempt_entry["error"] = parsed_error
        else:
            attempt_entry["error"] = f"compile failed for {to_repo_relative(sbpl_path, repo_root)}{detail}"
        attempts_log.append(attempt_entry)
        if signal_number is not None and signal_number in RETRY_SIGNALS and attempts <= retry_limit + 1:
            continue
        break
    payload = {
        "status": "error",
        "attempts": attempts,
        "retries_used": attempts - 1,
        "returncode": attempts_log[-1].get("returncode") if attempts_log else None,
        "signal": attempts_log[-1].get("signal") if attempts_log else None,
        "error": attempts_log[-1].get("error") if attempts_log else None,
    }
    if attempts_log and isinstance(attempts_log[-1].get("output"), Mapping):
        payload["output"] = attempts_log[-1]["output"]
    if attempts_log:
        payload["attempts_log"] = attempts_log
    return payload


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="encoder-write-trace")
    ap.add_argument(
        "--inputs",
        type=Path,
        default=Path("book/evidence/experiments/profile-pipeline/encoder-write-trace/inputs.json"),
        help="Input list (repo-relative)",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=Path("book/evidence/experiments/profile-pipeline/encoder-write-trace/out"),
        help="Output directory (repo-relative)",
    )
    ap.add_argument(
        "--mode",
        choices=("triage", "dynamic", "patch", "hw_breakpoint"),
        default="triage",
        help="Hook mode (triage only, dynamic interpose, address patch, or hardware breakpoint)",
    )
    ap.add_argument(
        "--write-addr",
        default=None,
        help="Absolute address for _sb_mutable_buffer_write (hex or decimal)",
    )
    ap.add_argument(
        "--write-unslid",
        default=None,
        help="Unslid VM address for _sb_mutable_buffer_write (hex or decimal)",
    )
    ap.add_argument(
        "--write-uuid",
        default=None,
        help="Expected libsandbox UUID for unslid address validation",
    )
    ap.add_argument(
        "--write-offset",
        default=None,
        help="Image-relative offset for _sb_mutable_buffer_write (hex or decimal)",
    )
    ap.add_argument(
        "--sandbox-path",
        default=None,
        help="Override libsandbox path (default /usr/lib/libsandbox.1.dylib)",
    )
    ap.add_argument(
        "--dyld-shared-region",
        choices=("use", "private", "avoid"),
        default=None,
        help="Override DYLD_SHARED_REGION for the compile subprocess",
    )
    ap.add_argument(
        "--bind-image",
        type=Path,
        default=None,
        help="Caller image for bind/indirect analysis (defaults to repo dyld-libs libsandbox)",
    )
    ap.add_argument(
        "--allow-zero-hits",
        action="store_true",
        help="Allow hook modes to proceed even when zero write records are observed",
    )
    ap.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help="Retries for compile subprocess on SIGSEGV/SIGTRAP",
    )
    ap.add_argument(
        "--only-id",
        default=None,
        help="Run only the input with this id",
    )
    ap.add_argument("--skip-build", action="store_true", help="Skip interposer build")
    args = ap.parse_args(argv)

    repo_root = find_repo_root()
    inputs_path = ensure_absolute(args.inputs, repo_root)
    out_dir = ensure_absolute(args.out_dir, repo_root)

    inputs = _load_inputs(inputs_path)
    expected_world = baseline_world_id(repo_root)
    if inputs.get("world_id") != expected_world:
        raise ValueError(f"inputs.json world_id mismatch: {inputs.get('world_id')} != {expected_world}")

    build_script = ensure_absolute(Path("book/evidence/experiments/profile-pipeline/encoder-write-trace/harness/build_interposer.sh"), repo_root)
    interposer = ensure_absolute(Path("book/evidence/experiments/profile-pipeline/encoder-write-trace/out/interposer/sbpl_trace_interpose.dylib"), repo_root)
    if not args.skip_build:
        subprocess.check_call([str(build_script)], cwd=repo_root)

    if args.bind_image is not None:
        bind_image = ensure_absolute(args.bind_image, repo_root)
    else:
        bind_candidate = ensure_absolute(DEFAULT_BIND_IMAGE, repo_root)
        bind_image = bind_candidate if bind_candidate.exists() else Path(args.sandbox_path or "/usr/lib/libsandbox.1.dylib")

    dyld_fallback = Path(args.sandbox_path or "/usr/lib/libsandbox.1.dylib")
    bind_analysis = _analyze_bind_tables(
        repo_root,
        bind_image,
        TARGET_SYMBOL,
        dyld_fallback=dyld_fallback,
        uuid_host_path=dyld_fallback,
    )
    auto_unslid: Optional[str] = None
    auto_immutable_unslid: Optional[str] = None
    write_unslid = args.write_unslid
    immutable_unslid: Optional[str] = None
    write_uuid = args.write_uuid
    uuid_info = bind_analysis.get("uuid")
    extracted_uuid = None
    if isinstance(uuid_info, Mapping):
        selected = uuid_info.get("extracted_selected")
        if isinstance(selected, Mapping):
            extracted_uuid = selected.get("uuid")
    if args.mode in ("patch", "hw_breakpoint") and not args.write_addr and not args.write_offset and not write_unslid:
        nm_info = bind_analysis.get("nm")
        if isinstance(nm_info, Mapping):
            candidate = nm_info.get("address")
            if isinstance(candidate, str) and extracted_uuid:
                auto_unslid = candidate
                write_unslid = candidate
                if not write_uuid:
                    write_uuid = extracted_uuid
    if args.mode in ("patch", "hw_breakpoint"):
        nm_secondary = bind_analysis.get("nm_secondary")
        if isinstance(nm_secondary, Mapping):
            candidate = nm_secondary.get("address")
            if isinstance(candidate, str) and extracted_uuid:
                auto_immutable_unslid = candidate
                immutable_unslid = candidate

    traces_dir = out_dir / "traces"
    blobs_dir = out_dir / "blobs"
    triage_dir = out_dir / "triage"
    stats_dir = out_dir / "stats"
    traces_dir.mkdir(parents=True, exist_ok=True)
    blobs_dir.mkdir(parents=True, exist_ok=True)
    triage_dir.mkdir(parents=True, exist_ok=True)
    stats_dir.mkdir(parents=True, exist_ok=True)

    entries: List[Dict[str, Any]] = []
    compile_ok = 0
    compile_error = 0
    compile_retries = 0
    for entry in inputs.get("inputs", []):
        if not isinstance(entry, Mapping):
            continue
        entry_id = entry.get("id")
        sbpl_rel = entry.get("sbpl")
        if not isinstance(entry_id, str) or not isinstance(sbpl_rel, str):
            continue
        if args.only_id and entry_id != args.only_id:
            continue

        sbpl_path = ensure_absolute(Path(sbpl_rel), repo_root)
        compile_config = entry.get("compile")
        compile_mode = "file"
        compile_params = None
        if isinstance(compile_config, Mapping):
            mode = compile_config.get("mode")
            if isinstance(mode, str):
                compile_mode = mode
            compile_params = _normalize_params(compile_config.get("params"))
        else:
            mode = entry.get("compile_mode")
            if isinstance(mode, str):
                compile_mode = mode
            compile_params = _normalize_params(entry.get("params"))
        if compile_mode not in ("file", "string"):
            raise ValueError(f"unsupported compile mode for {entry_id}: {compile_mode}")
        trace_path = traces_dir / f"{entry_id}.jsonl"
        out_blob = blobs_dir / f"{entry_id}.sb.bin"
        triage_path = triage_dir / f"{entry_id}.json"
        stats_path = stats_dir / f"{entry_id}.stats.json"

        if trace_path.exists():
            trace_path.unlink()
        if triage_path.exists():
            triage_path.unlink()
        if stats_path.exists():
            stats_path.unlink()

        compile_result = _run_compile(
            repo_root,
            interposer,
            sbpl_path,
            trace_path,
            stats_path,
            out_blob,
            compile_mode=compile_mode,
            compile_params=compile_params,
            mode=args.mode,
            write_addr=args.write_addr,
            write_unslid=write_unslid,
            write_uuid=write_uuid,
            write_offset=args.write_offset,
            immutable_unslid=immutable_unslid,
            sandbox_path=args.sandbox_path,
            dyld_shared_region=args.dyld_shared_region,
            triage_path=triage_path,
            retries=args.retries,
        )
        trace_records = 0
        if trace_path.exists():
            trace_records = sum(1 for line in trace_path.read_text().splitlines() if line.strip())
        stats_payload = None
        if stats_path.exists():
            try:
                stats_payload = json.loads(stats_path.read_text())
            except Exception:
                stats_payload = None
        _augment_triage(
            triage_path,
            bind_analysis,
            trace_records,
            mode=args.mode,
            require_hits=not args.allow_zero_hits and args.mode != "triage",
            compile_info=compile_result,
            stats=stats_payload,
        )
        compile_status = compile_result.get("status")
        if compile_status == "ok":
            compile_ok += 1
        else:
            compile_error += 1
        retries_used = compile_result.get("retries_used")
        if isinstance(retries_used, int):
            compile_retries += retries_used

        trace_present = trace_path.exists()
        stats_present = stats_path.exists()
        triage_present = triage_path.exists()

        entries.append(
            {
                "id": entry_id,
                "sbpl": to_repo_relative(sbpl_path, repo_root),
                "trace": to_repo_relative(trace_path, repo_root),
                "blob": to_repo_relative(out_blob, repo_root),
                "triage": to_repo_relative(triage_path, repo_root),
                "stats": to_repo_relative(stats_path, repo_root),
                "trace_records": trace_records,
                "compile": compile_result,
                "compile_config": {
                    "mode": compile_mode,
                    "params": compile_params,
                },
                "trace_integrity": {
                    "trace_present": trace_present,
                    "stats_present": stats_present,
                    "triage_present": triage_present,
                    "compile_status": compile_status,
                },
            }
        )

    manifest = {
        "world_id": expected_world,
        "inputs": entries,
        "inputs_file": to_repo_relative(inputs_path, repo_root),
        "triage_dir": to_repo_relative(triage_dir, repo_root),
        "trace_harness": {
            "interposer": to_repo_relative(interposer, repo_root),
            "mode": args.mode,
            "target_symbol": TARGET_SYMBOL,
            "bind_image": to_repo_relative(bind_image, repo_root),
            "compile_command": relativize_command(
                [sys.executable, "-m", "book.api.profile", "compile", "<sbpl>", "--out", "<blob>"],
                repo_root,
            ),
            "env": {
                "DYLD_INSERT_LIBRARIES": to_repo_relative(interposer, repo_root),
                "SBPL_TRACE_MODE": args.mode,
            },
            "retries": args.retries,
            "retry_signals": sorted(signal.Signals(sig).name for sig in RETRY_SIGNALS),
        },
    }
    if args.only_id:
        manifest["only_id"] = args.only_id
    if args.write_addr:
        manifest["trace_harness"]["env"]["SBPL_WRITE_ADDR"] = args.write_addr
    if write_unslid:
        manifest["trace_harness"]["env"]["SBPL_WRITE_UNSLID"] = write_unslid
        manifest["trace_harness"]["write_unslid_source"] = "nm" if auto_unslid else "cli"
    elif args.mode in ("patch", "hw_breakpoint") and not args.write_addr and not args.write_offset and not args.write_unslid:
        if not extracted_uuid:
            manifest["trace_harness"]["write_unslid_source"] = "skipped_uuid_missing"
    if immutable_unslid:
        manifest["trace_harness"]["env"]["SBPL_WRITE_IMMUTABLE_UNSLID"] = immutable_unslid
        manifest["trace_harness"]["immutable_unslid_source"] = "nm" if auto_immutable_unslid else "cli"
    if write_uuid:
        manifest["trace_harness"]["env"]["SBPL_WRITE_UUID_EXPECTED"] = write_uuid
    if args.dyld_shared_region:
        manifest["trace_harness"]["env"]["DYLD_SHARED_REGION"] = args.dyld_shared_region
    if args.write_offset:
        manifest["trace_harness"]["env"]["SBPL_WRITE_OFFSET"] = args.write_offset
    if args.sandbox_path:
        manifest["trace_harness"]["env"]["SBPL_SANDBOX_PATH"] = args.sandbox_path

    summary = {
        "world_id": expected_world,
        "counts": {
            "inputs": len(entries),
            "traces": len(entries),
            "blobs": len(entries),
            "triage": len(entries),
            "compile_ok": compile_ok,
            "compile_error": compile_error,
            "compile_retries": compile_retries,
        },
    }

    _write_json(out_dir / "manifest.json", manifest)
    _write_json(out_dir / "summary.json", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
