"""Wait/attach helper for EntitlementJail run-xpc without external tools."""

from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from book.api import path_utils

from ej_cli import EJ, REPO_ROOT, copy_file, extract_log_capture_path, home_hint, maybe_parse_json


def _read_lines(stream, sink: List[str], on_line: Optional[Callable[[str], None]] = None) -> None:
    for line in iter(stream.readline, ""):
        sink.append(line)
        if on_line is not None:
            on_line(line)


def parse_wait_ready_line(line: str) -> Optional[Dict[str, str]]:
    if "wait-ready" not in line:
        return None
    after = line.split("wait-ready", 1)[1].strip()
    out: Dict[str, str] = {}
    for token in after.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        out[key.strip()] = value.strip()
    if "wait_path" in out or "mode" in out:
        return out
    return None


def _extract_wait_spec(args: List[str]) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    wait_path = None
    wait_mode = None
    wait_timeout_ms: Optional[int] = None
    for idx, token in enumerate(args):
        if token == "--wait-fifo" and idx + 1 < len(args):
            wait_path = args[idx + 1]
            wait_mode = "fifo"
        elif token == "--wait-exists" and idx + 1 < len(args):
            wait_path = args[idx + 1]
            wait_mode = "exists"
        elif token == "--wait-timeout-ms" and idx + 1 < len(args):
            value = args[idx + 1]
            try:
                wait_timeout_ms = int(value)
            except Exception:
                wait_timeout_ms = None
        elif token == "--attach":
            wait_mode = wait_mode or "fifo"
    return wait_path, wait_mode, wait_timeout_ms


def _trigger_fifo(path: Path, *, nonblocking: bool = False) -> Optional[str]:
    try:
        flags = os.O_WRONLY
        if nonblocking:
            flags |= os.O_NONBLOCK
        fd = os.open(str(path), flags)
        try:
            os.write(fd, b"go")
        finally:
            os.close(fd)
        return None
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


def _trigger_exists(path: Path) -> Optional[str]:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("go")
        return None
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


def _run_wait_command(
    *,
    cmd: List[str],
    wait_path_hint: Optional[str],
    wait_mode_hint: Optional[str],
    wait_timeout_ms: Optional[int],
    log_path: Optional[Path],
    capture_path: Optional[Path],
    plan_id: str,
    row_id: str,
    trigger_delay_s: float,
    post_trigger: bool,
    post_trigger_delay_s: float,
    wait_ready_timeout_s: float,
    process_timeout_s: Optional[float],
    extra_meta: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    start_ts = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except Exception as exc:
        return {
            "command": path_utils.relativize_command(cmd, REPO_ROOT),
            "error": f"{type(exc).__name__}: {exc}",
        }

    stdout_lines: List[str] = []
    stderr_lines: List[str] = []
    wait_info: Dict[str, object] = {}
    wait_event = threading.Event()

    def _on_stderr(line: str) -> None:
        parsed = parse_wait_ready_line(line)
        if parsed and not wait_event.is_set():
            wait_info.update(parsed)
            wait_info["wait_ready_line"] = line.strip()
            wait_info["wait_ready_at_unix_s"] = time.time()
            wait_event.set()

    t_out = threading.Thread(target=_read_lines, args=(proc.stdout, stdout_lines))
    t_err = threading.Thread(target=_read_lines, args=(proc.stderr, stderr_lines, _on_stderr))
    t_out.start()
    t_err.start()

    while True:
        if wait_event.is_set():
            break
        if proc.poll() is not None:
            break
        if time.time() - start_ts > wait_ready_timeout_s:
            wait_info["wait_ready_timeout_s"] = wait_ready_timeout_s
            break
        time.sleep(0.05)

    wait_path = wait_info.get("wait_path") or wait_path_hint
    wait_mode = wait_info.get("mode") or wait_mode_hint

    trigger_events: List[Dict[str, object]] = []
    if wait_path is None:
        wait_info["wait_ready_missing"] = True
    else:
        if proc.poll() is None:
            if trigger_delay_s > 0:
                time.sleep(trigger_delay_s)
            trigger_at = time.time()
            if wait_mode == "fifo":
                trigger_error = _trigger_fifo(Path(str(wait_path)))
            else:
                trigger_error = _trigger_exists(Path(str(wait_path)))
            trigger_events.append(
                {
                    "kind": "primary",
                    "at_unix_s": trigger_at,
                    "error": trigger_error,
                }
            )
            if post_trigger:
                if post_trigger_delay_s > 0:
                    time.sleep(post_trigger_delay_s)
                post_at = time.time()
                if wait_mode == "fifo":
                    post_error = _trigger_fifo(Path(str(wait_path)), nonblocking=True)
                else:
                    post_error = _trigger_exists(Path(str(wait_path)))
                trigger_events.append(
                    {
                        "kind": "post",
                        "at_unix_s": post_at,
                        "error": post_error,
                    }
                )
        else:
            wait_info["trigger_skipped"] = "process_exited"

    derived_timeout_s = None
    if wait_timeout_ms is not None:
        derived_timeout_s = wait_timeout_ms / 1000.0 + max(trigger_delay_s, 0.0) + 5.0
    effective_timeout_s = process_timeout_s or 25.0
    if derived_timeout_s is not None:
        effective_timeout_s = max(effective_timeout_s, derived_timeout_s)

    try:
        proc.wait(timeout=effective_timeout_s)
    except Exception as exc:
        wait_info["wait_process_error"] = f"{type(exc).__name__}: {exc}"
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

    t_out.join(timeout=2)
    t_err.join(timeout=2)

    stdout_text = "".join(stdout_lines).strip()
    stderr_text = "".join(stderr_lines).strip()
    stdout_json = maybe_parse_json(stdout_text)

    log_copy_error = None
    if log_path is not None:
        if capture_path is None:
            capture_source = extract_log_capture_path(stdout_json)
            if capture_source:
                capture_path = Path(capture_source)
        if capture_path is not None:
            log_copy_error = copy_file(capture_path, log_path)
        else:
            log_copy_error = "log_capture_path_missing"

    finished_ts = time.time()

    record: Dict[str, object] = {
        "command": path_utils.relativize_command(cmd, REPO_ROOT),
        "plan_id": plan_id,
        "row_id": row_id,
        "exit_code": proc.returncode,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "stdout_json": stdout_json,
        "stdout_json_error": None if stdout_json is not None else ("stdout_empty" if not stdout_text else "stdout_not_json"),
        "wait_ready_line": wait_info.get("wait_ready_line"),
        "wait_path": wait_path,
        "wait_mode": wait_mode,
        "wait_ready_at_unix_s": wait_info.get("wait_ready_at_unix_s"),
        "trigger_events": trigger_events,
        "wait_info": wait_info,
        "wait_timeout_ms": wait_timeout_ms,
        "trigger_delay_s": trigger_delay_s,
        "post_trigger": post_trigger,
        "post_trigger_delay_s": post_trigger_delay_s if post_trigger else None,
        "wait_ready_timeout_s": wait_ready_timeout_s,
        "process_timeout_s": effective_timeout_s,
        "started_at_unix_s": start_ts,
        "finished_at_unix_s": finished_ts,
        "duration_s": finished_ts - start_ts,
        "log_path": path_utils.to_repo_relative(log_path, REPO_ROOT) if log_path else None,
        "log_capture_source": home_hint(capture_path) if capture_path else None,
        "log_copy_error": log_copy_error,
    }
    if extra_meta:
        record.update(extra_meta)
    return record


def _prepare_log_capture(cmd: List[str], log_path: Optional[Path]) -> Tuple[List[str], Optional[Path]]:
    if log_path is None:
        return cmd, None
    log_name = log_path.name
    return cmd + ["--log-path-class", "tmp", "--log-name", log_name], None


def run_wait_xpc(
    *,
    profile_id: Optional[str],
    service_id: str,
    probe_id: str,
    probe_args: List[str],
    wait_args: List[str],
    log_path: Optional[Path],
    plan_id: str,
    row_id: str,
    trigger_delay_s: float = 0.0,
    post_trigger: bool = False,
    post_trigger_delay_s: float = 0.2,
    wait_ready_timeout_s: float = 15.0,
    process_timeout_s: Optional[float] = None,
    use_profile: bool = True,
) -> Dict[str, object]:
    cmd = [str(EJ), "run-xpc"]
    cmd, capture_path = _prepare_log_capture(cmd, log_path)
    cmd += ["--plan-id", plan_id, "--row-id", row_id, *wait_args]
    if use_profile and profile_id:
        cmd += ["--profile", profile_id]
    else:
        cmd.append(service_id)
    cmd += [probe_id, *probe_args]

    wait_path_hint, wait_mode_hint, wait_timeout_ms = _extract_wait_spec(wait_args)
    return _run_wait_command(
        cmd=cmd,
        wait_path_hint=wait_path_hint,
        wait_mode_hint=wait_mode_hint,
        wait_timeout_ms=wait_timeout_ms,
        log_path=log_path,
        capture_path=capture_path,
        plan_id=plan_id,
        row_id=row_id,
        trigger_delay_s=trigger_delay_s,
        post_trigger=post_trigger,
        post_trigger_delay_s=post_trigger_delay_s,
        wait_ready_timeout_s=wait_ready_timeout_s,
        process_timeout_s=process_timeout_s,
        extra_meta={
            "profile_id": profile_id,
            "service_id": service_id,
            "probe_id": probe_id,
            "probe_args": list(probe_args),
            "wait_args": list(wait_args),
        },
    )


def run_probe_wait(
    *,
    profile_id: Optional[str],
    service_id: str,
    probe_id: str,
    probe_args: List[str],
    log_path: Optional[Path],
    plan_id: str,
    row_id: str,
    trigger_delay_s: float = 0.0,
    post_trigger: bool = False,
    post_trigger_delay_s: float = 0.2,
    wait_ready_timeout_s: float = 10.0,
    process_timeout_s: Optional[float] = None,
    use_profile: bool = True,
) -> Dict[str, object]:
    cmd = [str(EJ), "run-xpc"]
    cmd, capture_path = _prepare_log_capture(cmd, log_path)
    cmd += ["--plan-id", plan_id, "--row-id", row_id]
    if use_profile and profile_id:
        cmd += ["--profile", profile_id]
    else:
        cmd.append(service_id)
    cmd += [probe_id, *probe_args]

    wait_path_hint, wait_mode_hint, wait_timeout_ms = _extract_wait_spec(probe_args)
    return _run_wait_command(
        cmd=cmd,
        wait_path_hint=wait_path_hint,
        wait_mode_hint=wait_mode_hint,
        wait_timeout_ms=wait_timeout_ms,
        log_path=log_path,
        capture_path=capture_path,
        plan_id=plan_id,
        row_id=row_id,
        trigger_delay_s=trigger_delay_s,
        post_trigger=post_trigger,
        post_trigger_delay_s=post_trigger_delay_s,
        wait_ready_timeout_s=wait_ready_timeout_s,
        process_timeout_s=process_timeout_s,
        extra_meta={
            "profile_id": profile_id,
            "service_id": service_id,
            "probe_id": probe_id,
            "probe_args": list(probe_args),
            "wait_args_source": "probe_args",
        },
    )
