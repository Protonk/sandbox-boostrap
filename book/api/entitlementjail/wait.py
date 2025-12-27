"""
Wait/attach helpers for EntitlementJail `xpc session`.

EntitlementJail v2 replaces the v1 `run-xpc --attach/--wait-*` flow with
`entitlement-jail xpc session`, which provides:

- a stable service PID for attach tooling, and
- an explicit wait barrier (`--wait ...`) with JSONL lifecycle events.

This module keeps the experiment-facing API stable (`run_wait_xpc`,
`run_probe_wait`) while implementing them in terms of the session control
plane.
"""

from __future__ import annotations

import errno
import json
import os
import select
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from book.api import path_utils
from book.api.entitlementjail.logging import (
    LOG_OBSERVER_LAST,
    extract_correlation_id,
    extract_process_name,
    extract_service_pid,
    observer_status,
    run_sandbox_log_observer,
    should_run_observer,
)
from book.api.entitlementjail.paths import EJ, REPO_ROOT


def _read_lines(stream, sink: List[str]) -> None:
    for line in iter(stream.readline, ""):
        sink.append(line)


def _extract_flag_value(args: List[str], flag: str) -> Optional[str]:
    for idx, token in enumerate(args):
        if token == flag and idx + 1 < len(args):
            return args[idx + 1]
    return None


def _extract_flag_int(args: List[str], flag: str) -> Optional[int]:
    value = _extract_flag_value(args, flag)
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _trigger_fifo(path: Path, *, nonblocking: bool, timeout_s: float) -> Optional[str]:
    try:
        flags = os.O_WRONLY | os.O_NONBLOCK
        deadline = time.monotonic() + max(timeout_s, 0.0)
        while True:
            try:
                fd = os.open(str(path), flags)
            except OSError as exc:
                if nonblocking:
                    return f"{type(exc).__name__}: {exc}"
                if exc.errno == errno.ENXIO and time.monotonic() <= deadline:
                    time.sleep(0.05)
                    continue
                return f"{type(exc).__name__}: {exc}"
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


def _readline_with_timeout(stream, timeout_s: float) -> Optional[str]:
    # `select()` on a text-mode pipe does not account for data already buffered
    # in the TextIOWrapper. Prefer consuming buffered bytes first.
    try:
        buf = getattr(stream, "buffer", None)
        if buf is not None:
            try:
                if buf.peek(1):
                    line = stream.readline()
                    return line if line else None
            except Exception:
                pass
    except Exception:
        pass
    try:
        rlist, _, _ = select.select([stream], [], [], timeout_s)
    except Exception:
        rlist = [stream]
    if not rlist:
        return None
    line = stream.readline()
    return line if line else None


def _session_cmd(
    *,
    profile_id: Optional[str],
    service_id: Optional[str],
    ack_risk: Optional[str],
    plan_id: str,
    correlation_id: Optional[str],
    wait_spec: Optional[str],
    wait_timeout_ms: Optional[int],
    wait_interval_ms: Optional[int],
    xpc_timeout_ms: Optional[int],
) -> List[str]:
    if (profile_id is None) == (service_id is None):
        raise ValueError("Provide exactly one of profile_id or service_id")
    cmd = [str(EJ), "xpc", "session"]
    if ack_risk:
        cmd += ["--ack-risk", ack_risk]
    cmd += ["--plan-id", plan_id]
    if correlation_id:
        cmd += ["--correlation-id", correlation_id]
    if wait_spec:
        cmd += ["--wait", wait_spec]
    if wait_timeout_ms is not None:
        cmd += ["--wait-timeout-ms", str(wait_timeout_ms)]
    if wait_interval_ms is not None:
        cmd += ["--wait-interval-ms", str(wait_interval_ms)]
    if xpc_timeout_ms is not None:
        cmd += ["--xpc-timeout-ms", str(xpc_timeout_ms)]
    if profile_id is not None:
        cmd += ["--profile", profile_id]
    else:
        cmd += ["--service", service_id]
    return cmd


def _extract_wait_spec_from_probe_args(probe_args: List[str]) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
    # Used by run_probe_wait (probe-internal waits like fs_op_wait).
    fifo_path = _extract_flag_value(probe_args, "--wait-fifo")
    if fifo_path is not None:
        return fifo_path, "fifo", _extract_flag_int(probe_args, "--wait-timeout-ms"), _extract_flag_int(probe_args, "--wait-interval-ms")
    exists_path = _extract_flag_value(probe_args, "--wait-exists")
    if exists_path is not None:
        return exists_path, "exists", _extract_flag_int(probe_args, "--wait-timeout-ms"), _extract_flag_int(probe_args, "--wait-interval-ms")
    return None, None, _extract_flag_int(probe_args, "--wait-timeout-ms"), _extract_flag_int(probe_args, "--wait-interval-ms")


def _wait_for_session_ready(
    *,
    proc: subprocess.Popen,
    stdout_lines: List[str],
    stdout_jsonl: List[Dict[str, object]],
    wait_for_wait_ready: bool,
    wait_ready_timeout_s: float,
) -> Tuple[Optional[Dict[str, object]], Optional[Dict[str, object]], Optional[str]]:
    session_ready = None
    wait_ready = None
    deadline = time.monotonic() + max(wait_ready_timeout_s, 0.0)
    while time.monotonic() <= deadline:
        line = _readline_with_timeout(proc.stdout, timeout_s=0.2)  # type: ignore[arg-type]
        if line is None:
            if proc.poll() is not None:
                break
            continue
        stdout_lines.append(line)
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except Exception:
            continue
        if isinstance(obj, dict):
            stdout_jsonl.append(obj)
            if obj.get("kind") == "xpc_session_event":
                data = obj.get("data")
                if isinstance(data, dict):
                    event = data.get("event")
                    if event == "session_ready":
                        session_ready = obj
                    elif event == "wait_ready":
                        wait_ready = obj
        if session_ready is not None and (not wait_for_wait_ready or wait_ready is not None):
            return session_ready, wait_ready, None
    if proc.poll() is not None:
        return session_ready, wait_ready, "process_exited"
    return session_ready, wait_ready, "timeout"


def _trigger_session_wait(
    *,
    wait_path: str,
    wait_mode: str,
    nonblocking: bool,
    timeout_s: float,
) -> Optional[str]:
    path = Path(wait_path)
    if wait_mode == "fifo":
        return _trigger_fifo(path, nonblocking=nonblocking, timeout_s=timeout_s)
    return _trigger_exists(path)


def _run_session(
    *,
    session_cmd: List[str],
    run_probe_cmd: Dict[str, object],
    plan_id: str,
    row_id: Optional[str],
    wait_path: Optional[str],
    wait_mode: Optional[str],
    wait_timeout_ms: Optional[int],
    trigger_delay_s: float,
    post_trigger: bool,
    post_trigger_delay_s: float,
    wait_ready_timeout_s: float,
    process_timeout_s: Optional[float],
    log_path: Optional[Path],
    on_wait_ready: Optional[Callable[[Dict[str, object]], None]],
    on_trigger: Optional[Callable[[Dict[str, object]], None]],
    observer_window_last: str,
    observer_start_s: Optional[float] = None,
) -> Dict[str, object]:
    started_at_unix_s = time.time()
    stdout_lines: List[str] = []
    stderr_lines: List[str] = []
    stdout_jsonl: List[Dict[str, object]] = []
    session_ready: Optional[Dict[str, object]] = None
    wait_ready: Optional[Dict[str, object]] = None
    probe_response: Optional[Dict[str, object]] = None
    wait_info: Dict[str, object] = {}
    trigger_events: List[Dict[str, object]] = []

    try:
        proc = subprocess.Popen(
            session_cmd,
            cwd=str(REPO_ROOT),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except Exception as exc:
        return {
            "command": path_utils.relativize_command(session_cmd, REPO_ROOT),
            "error": f"{type(exc).__name__}: {exc}",
        }
    assert proc.stdin and proc.stdout and proc.stderr

    t_err = threading.Thread(target=_read_lines, args=(proc.stderr, stderr_lines))
    t_err.start()

    wait_for_wait_ready = wait_mode is not None
    session_ready, wait_ready, ready_error = _wait_for_session_ready(
        proc=proc,
        stdout_lines=stdout_lines,
        stdout_jsonl=stdout_jsonl,
        wait_for_wait_ready=wait_for_wait_ready,
        wait_ready_timeout_s=wait_ready_timeout_s,
    )

    if session_ready and isinstance(session_ready.get("data"), dict):
        wait_info["session_ready"] = session_ready.get("data")
    if wait_ready and isinstance(wait_ready.get("data"), dict):
        wait_info["wait_ready"] = wait_ready.get("data")

    if ready_error:
        wait_info["ready_error"] = ready_error

    # If the caller didn't provide a wait path (session wait barrier disabled), proceed.
    if wait_path is None and wait_mode is None:
        wait_info["wait_mode"] = None
        wait_info["wait_path"] = None
    else:
        if wait_path is None or wait_mode is None:
            # Prefer values from the wait_ready event when available.
            if wait_ready and isinstance(wait_ready.get("data"), dict):
                data = wait_ready["data"]
                wait_path = data.get("wait_path") if isinstance(data.get("wait_path"), str) else wait_path
            if wait_mode is None and wait_path is not None:
                wait_mode = "fifo" if wait_path.endswith(".fifo") else "exists"

        wait_info["wait_mode"] = wait_mode
        wait_info["wait_path"] = wait_path
        wait_info["wait_timeout_ms"] = wait_timeout_ms

        if wait_ready and on_wait_ready is not None and wait_path is not None and wait_mode is not None:
            cb = {
                "wait_path": wait_path,
                "wait_mode": wait_mode,
                "wait_timeout_ms": wait_timeout_ms,
                "session_ready": wait_info.get("session_ready"),
                "wait_ready": wait_info.get("wait_ready"),
            }
            try:
                on_wait_ready(cb)
                wait_info["on_wait_ready_called"] = True
            except Exception as exc:
                wait_info["on_wait_ready_error"] = f"{type(exc).__name__}: {exc}"

        if proc.poll() is None and wait_path is not None and wait_mode is not None:
            if trigger_delay_s > 0:
                time.sleep(trigger_delay_s)
            trigger_at = time.time()
            trigger_error = _trigger_session_wait(
                wait_path=wait_path,
                wait_mode=wait_mode,
                nonblocking=False,
                timeout_s=2.0,
            )
            trigger_events.append({"kind": "primary", "at_unix_s": trigger_at, "error": trigger_error})
            if on_trigger is not None:
                cb = {
                    "wait_path": wait_path,
                    "wait_mode": wait_mode,
                    "wait_timeout_ms": wait_timeout_ms,
                    "trigger": trigger_events[-1],
                    "trigger_events": list(trigger_events),
                }
                try:
                    on_trigger(cb)
                    wait_info["on_trigger_called"] = True
                except Exception as exc:
                    wait_info["on_trigger_error"] = f"{type(exc).__name__}: {exc}"
            if post_trigger:
                if post_trigger_delay_s > 0:
                    time.sleep(post_trigger_delay_s)
                post_at = time.time()
                post_error = _trigger_session_wait(
                    wait_path=wait_path,
                    wait_mode=wait_mode,
                    nonblocking=True,
                    timeout_s=0.0,
                )
                trigger_events.append({"kind": "post", "at_unix_s": post_at, "error": post_error})

            # Avoid a race where the trigger is written but the session has not
            # yet processed it; probes can return `session_not_triggered` until
            # the `trigger_received` event is observed.
            if trigger_error is None:
                trigger_deadline = time.monotonic() + 2.0
                while time.monotonic() <= trigger_deadline:
                    line = _readline_with_timeout(proc.stdout, timeout_s=0.2)
                    if line is None:
                        if proc.poll() is not None:
                            break
                        continue
                    stdout_lines.append(line)
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        obj = json.loads(stripped)
                    except Exception:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    stdout_jsonl.append(obj)
                    if obj.get("kind") != "xpc_session_event":
                        continue
                    data = obj.get("data")
                    if isinstance(data, dict) and data.get("event") == "trigger_received":
                        wait_info["trigger_received"] = data
                        break

    # Run the probe.
    probe_started_at_unix_s = time.time()
    try:
        proc.stdin.write(json.dumps(run_probe_cmd) + "\n")
        proc.stdin.flush()
    except Exception as exc:
        wait_info["stdin_write_error"] = f"{type(exc).__name__}: {exc}"

    deadline = time.monotonic() + (process_timeout_s or 25.0)
    while time.monotonic() <= deadline:
        line = _readline_with_timeout(proc.stdout, timeout_s=0.2)
        if line is None:
            if proc.poll() is not None:
                break
            continue
        stdout_lines.append(line)
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except Exception:
            continue
        if isinstance(obj, dict):
            stdout_jsonl.append(obj)
            if obj.get("kind") == "probe_response":
                probe_response = obj
                break

    probe_finished_at_unix_s = time.time()

    # Capture deny evidence (observer-only) for this probe window.
    observer: Optional[Dict[str, object]] = None
    observer_log_path = None
    if log_path is not None and should_run_observer():
        observer_dest = log_path.parent / "observer" / f"{log_path.name}.observer.json"
        observer_log_path = path_utils.to_repo_relative(observer_dest, REPO_ROOT)
        observer_correlation_id = extract_correlation_id(probe_response)
        observer = run_sandbox_log_observer(
            pid=extract_service_pid(probe_response),
            process_name=extract_process_name(probe_response),
            dest_path=observer_dest,
            last=observer_window_last,
            start_s=observer_start_s or probe_started_at_unix_s,
            end_s=probe_finished_at_unix_s,
            plan_id=plan_id,
            row_id=row_id,
            correlation_id=observer_correlation_id,
        )

    # Close session (best-effort).
    try:
        proc.stdin.write(json.dumps({"command": "close_session"}) + "\n")
        proc.stdin.flush()
    except Exception:
        pass

    # Drain a little more output.
    drain_deadline = time.monotonic() + 2.0
    while time.monotonic() <= drain_deadline:
        line = _readline_with_timeout(proc.stdout, timeout_s=0.1)
        if line is None:
            break
        stdout_lines.append(line)
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except Exception:
            continue
        if isinstance(obj, dict):
            stdout_jsonl.append(obj)

    # Wait for the session process to exit; terminate if it lingers.
    exit_code = None
    try:
        proc.wait(timeout=2.0)
        exit_code = proc.returncode
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=2.0)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        exit_code = proc.returncode

    t_err.join(timeout=1.0)

    stdout_text = "".join(stdout_lines).rstrip()
    stderr_text = "".join(stderr_lines).rstrip()

    log_write_error = None
    if log_path is not None and stdout_text:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(stdout_text + "\n")
        except Exception as exc:
            log_write_error = f"{type(exc).__name__}: {exc}"

    record: Dict[str, object] = {
        "command": path_utils.relativize_command(session_cmd, REPO_ROOT),
        "exit_code": exit_code,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "plan_id": plan_id,
        "row_id": row_id,
        "log_path": path_utils.to_repo_relative(log_path, REPO_ROOT) if log_path else None,
        "log_write_error": log_write_error,
        "observer": observer,
        "observer_log_path": observer_log_path,
        "observer_status": observer_status(observer),
        "wait_info": wait_info,
        "trigger_events": trigger_events,
        "probe_started_at_unix_s": probe_started_at_unix_s,
        "probe_finished_at_unix_s": probe_finished_at_unix_s,
        "started_at_unix_s": started_at_unix_s,
        "finished_at_unix_s": time.time(),
        "duration_s": time.time() - started_at_unix_s,
        "stdout_jsonl_kinds": {k: sum(1 for o in stdout_jsonl if o.get("kind") == k) for k in {o.get("kind") for o in stdout_jsonl if isinstance(o, dict)}},
    }

    if probe_response is not None:
        record["stdout_json"] = probe_response
    else:
        record["stdout_json_error"] = "probe_response_missing"

    return record


def run_wait_xpc(
    *,
    profile_id: Optional[str] = None,
    service_id: Optional[str] = None,
    probe_id: str,
    probe_args: Sequence[str] = (),
    wait_spec: Optional[str] = None,
    wait_timeout_ms: Optional[int] = None,
    wait_interval_ms: Optional[int] = None,
    xpc_timeout_ms: Optional[int] = None,
    ack_risk: Optional[str] = None,
    log_path: Optional[Path] = None,
    plan_id: str,
    row_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    trigger_delay_s: float = 0.0,
    post_trigger: bool = False,
    post_trigger_delay_s: float = 0.2,
    wait_ready_timeout_s: float = 15.0,
    process_timeout_s: Optional[float] = None,
    on_wait_ready: Optional[Callable[[Dict[str, object]], None]] = None,
    on_trigger: Optional[Callable[[Dict[str, object]], None]] = None,
) -> Dict[str, object]:
    """Run a single probe via an `xpc session` with a session wait barrier."""
    session_cmd = _session_cmd(
        profile_id=profile_id,
        service_id=service_id,
        ack_risk=ack_risk,
        plan_id=plan_id,
        correlation_id=correlation_id,
        wait_spec=wait_spec,
        wait_timeout_ms=wait_timeout_ms,
        wait_interval_ms=wait_interval_ms,
        xpc_timeout_ms=xpc_timeout_ms,
    )
    run_probe_cmd = {"command": "run_probe", "probe_id": probe_id, "argv": list(probe_args)}

    # Extract wait_path/mode for callback metadata (prefer wait_ready event at runtime).
    wait_path = None
    wait_mode = None
    if wait_spec:
        if wait_spec.startswith("fifo:"):
            wait_mode = "fifo"
            wait_path = wait_spec.split("fifo:", 1)[1]
            if wait_path == "auto":
                wait_path = None
        elif wait_spec.startswith("exists:"):
            wait_mode = "exists"
            wait_path = wait_spec.split("exists:", 1)[1]

    record = _run_session(
        session_cmd=session_cmd,
        run_probe_cmd=run_probe_cmd,
        plan_id=plan_id,
        row_id=row_id,
        wait_path=wait_path,
        wait_mode=wait_mode,
        wait_timeout_ms=wait_timeout_ms,
        trigger_delay_s=trigger_delay_s,
        post_trigger=post_trigger,
        post_trigger_delay_s=post_trigger_delay_s,
        wait_ready_timeout_s=wait_ready_timeout_s,
        process_timeout_s=process_timeout_s,
        log_path=log_path,
        on_wait_ready=on_wait_ready,
        on_trigger=on_trigger,
        observer_window_last=LOG_OBSERVER_LAST,
    )
    record.update(
        {
            "profile_id": profile_id,
            "service_id": service_id,
            "probe_id": probe_id,
            "probe_args": list(probe_args),
            "wait_spec": wait_spec,
            "wait_timeout_ms": wait_timeout_ms,
            "wait_interval_ms": wait_interval_ms,
            "xpc_timeout_ms": xpc_timeout_ms,
            "ack_risk": ack_risk,
            "correlation_id": correlation_id,
        }
    )
    return record


def run_probe_wait(
    *,
    profile_id: Optional[str] = None,
    service_id: Optional[str] = None,
    probe_id: str,
    probe_args: List[str],
    log_path: Optional[Path] = None,
    plan_id: str,
    row_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    ack_risk: Optional[str] = None,
    xpc_timeout_ms: Optional[int] = None,
    trigger_delay_s: float = 0.0,
    post_trigger: bool = False,
    post_trigger_delay_s: float = 0.2,
    wait_ready_timeout_s: float = 10.0,
    process_timeout_s: Optional[float] = None,
    on_wait_ready: Optional[Callable[[Dict[str, object]], None]] = None,
    on_trigger: Optional[Callable[[Dict[str, object]], None]] = None,
) -> Dict[str, object]:
    """Run a probe that carries its own wait flags (for example `fs_op_wait`)."""
    wait_path, wait_mode, wait_timeout_ms, _ = _extract_wait_spec_from_probe_args(probe_args)
    session_cmd = _session_cmd(
        profile_id=profile_id,
        service_id=service_id,
        ack_risk=ack_risk,
        plan_id=plan_id,
        correlation_id=correlation_id,
        wait_spec=None,
        wait_timeout_ms=None,
        wait_interval_ms=None,
        xpc_timeout_ms=xpc_timeout_ms,
    )
    run_probe_cmd = {"command": "run_probe", "probe_id": probe_id, "argv": list(probe_args)}

    started_at_unix_s = time.time()
    stdout_lines: List[str] = []
    stderr_lines: List[str] = []
    stdout_jsonl: List[Dict[str, object]] = []
    wait_info: Dict[str, object] = {
        "wait_args_source": "probe_args",
        "wait_path": wait_path,
        "wait_mode": wait_mode,
        "wait_timeout_ms": wait_timeout_ms,
    }
    trigger_events: List[Dict[str, object]] = []
    probe_response: Optional[Dict[str, object]] = None

    try:
        proc = subprocess.Popen(
            session_cmd,
            cwd=str(REPO_ROOT),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except Exception as exc:
        return {
            "command": path_utils.relativize_command(session_cmd, REPO_ROOT),
            "error": f"{type(exc).__name__}: {exc}",
        }
    assert proc.stdin and proc.stdout and proc.stderr

    t_err = threading.Thread(target=_read_lines, args=(proc.stderr, stderr_lines))
    t_err.start()

    # Session setup (no session wait barrier here).
    session_ready, _, ready_error = _wait_for_session_ready(
        proc=proc,
        stdout_lines=stdout_lines,
        stdout_jsonl=stdout_jsonl,
        wait_for_wait_ready=False,
        wait_ready_timeout_s=wait_ready_timeout_s,
    )
    if session_ready and isinstance(session_ready.get("data"), dict):
        wait_info["session_ready"] = session_ready.get("data")
    if ready_error:
        wait_info["ready_error"] = ready_error

    if on_wait_ready is not None and wait_path and wait_mode:
        try:
            on_wait_ready({"wait_path": wait_path, "wait_mode": wait_mode, "wait_timeout_ms": wait_timeout_ms})
            wait_info["on_wait_ready_called"] = True
        except Exception as exc:
            wait_info["on_wait_ready_error"] = f"{type(exc).__name__}: {exc}"

    probe_started_at_unix_s = time.time()
    try:
        proc.stdin.write(json.dumps(run_probe_cmd) + "\n")
        proc.stdin.flush()
    except Exception as exc:
        wait_info["stdin_write_error"] = f"{type(exc).__name__}: {exc}"

    derived_timeout_s = None
    if wait_timeout_ms is not None:
        derived_timeout_s = wait_timeout_ms / 1000.0 + max(trigger_delay_s, 0.0) + 5.0
    effective_timeout_s = process_timeout_s or 25.0
    if derived_timeout_s is not None:
        effective_timeout_s = max(effective_timeout_s, derived_timeout_s)
    deadline = time.monotonic() + effective_timeout_s

    trigger_scheduled_at = time.monotonic() + max(trigger_delay_s, 0.0)
    triggered = False
    post_trigger_scheduled_at = None

    while time.monotonic() <= deadline:
        now = time.monotonic()
        if not triggered and wait_path and wait_mode and now >= trigger_scheduled_at:
            trigger_at = time.time()
            trigger_error = _trigger_session_wait(
                wait_path=wait_path,
                wait_mode=wait_mode,
                nonblocking=False,
                timeout_s=2.0,
            )
            trigger_events.append({"kind": "primary", "at_unix_s": trigger_at, "error": trigger_error})
            triggered = True
            if on_trigger is not None:
                try:
                    on_trigger({"wait_path": wait_path, "wait_mode": wait_mode, "trigger": trigger_events[-1]})
                    wait_info["on_trigger_called"] = True
                except Exception as exc:
                    wait_info["on_trigger_error"] = f"{type(exc).__name__}: {exc}"
            if post_trigger:
                post_trigger_scheduled_at = time.monotonic() + max(post_trigger_delay_s, 0.0)

        if post_trigger_scheduled_at is not None and wait_path and wait_mode and now >= post_trigger_scheduled_at:
            post_at = time.time()
            post_error = _trigger_session_wait(
                wait_path=wait_path,
                wait_mode=wait_mode,
                nonblocking=True,
                timeout_s=0.0,
            )
            trigger_events.append({"kind": "post", "at_unix_s": post_at, "error": post_error})
            post_trigger_scheduled_at = None

        line = _readline_with_timeout(proc.stdout, timeout_s=0.2)
        if line is None:
            if proc.poll() is not None:
                break
            continue
        stdout_lines.append(line)
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except Exception:
            continue
        if isinstance(obj, dict):
            stdout_jsonl.append(obj)
            if obj.get("kind") == "probe_response":
                probe_response = obj
                break

    probe_finished_at_unix_s = time.time()

    # Deny evidence capture for the probe window.
    observer: Optional[Dict[str, object]] = None
    observer_log_path = None
    if log_path is not None and should_run_observer():
        observer_dest = log_path.parent / "observer" / f"{log_path.name}.observer.json"
        observer_log_path = path_utils.to_repo_relative(observer_dest, REPO_ROOT)
        observer = run_sandbox_log_observer(
            pid=extract_service_pid(probe_response),
            process_name=extract_process_name(probe_response),
            dest_path=observer_dest,
            last=LOG_OBSERVER_LAST,
            start_s=probe_started_at_unix_s,
            end_s=probe_finished_at_unix_s,
            plan_id=plan_id,
            row_id=row_id,
            correlation_id=extract_correlation_id(probe_response),
        )

    # Close session (best-effort) and drain.
    try:
        proc.stdin.write(json.dumps({"command": "close_session"}) + "\n")
        proc.stdin.flush()
    except Exception:
        pass

    drain_deadline = time.monotonic() + 2.0
    while time.monotonic() <= drain_deadline:
        line = _readline_with_timeout(proc.stdout, timeout_s=0.1)
        if line is None:
            break
        stdout_lines.append(line)
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except Exception:
            continue
        if isinstance(obj, dict):
            stdout_jsonl.append(obj)

    exit_code = None
    try:
        proc.wait(timeout=2.0)
        exit_code = proc.returncode
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=2.0)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        exit_code = proc.returncode

    t_err.join(timeout=1.0)

    stdout_text = "".join(stdout_lines).rstrip()
    stderr_text = "".join(stderr_lines).rstrip()

    log_write_error = None
    if log_path is not None and stdout_text:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(stdout_text + "\n")
        except Exception as exc:
            log_write_error = f"{type(exc).__name__}: {exc}"

    record: Dict[str, object] = {
        "command": path_utils.relativize_command(session_cmd, REPO_ROOT),
        "exit_code": exit_code,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "plan_id": plan_id,
        "row_id": row_id,
        "log_path": path_utils.to_repo_relative(log_path, REPO_ROOT) if log_path else None,
        "log_write_error": log_write_error,
        "observer": observer,
        "observer_log_path": observer_log_path,
        "observer_status": observer_status(observer),
        "wait_info": wait_info,
        "trigger_events": trigger_events,
        "probe_started_at_unix_s": probe_started_at_unix_s,
        "probe_finished_at_unix_s": probe_finished_at_unix_s,
        "started_at_unix_s": started_at_unix_s,
        "finished_at_unix_s": time.time(),
        "duration_s": time.time() - started_at_unix_s,
        "stdout_jsonl_kinds": {k: sum(1 for o in stdout_jsonl if o.get("kind") == k) for k in {o.get("kind") for o in stdout_jsonl if isinstance(o, dict)}},
        "profile_id": profile_id,
        "service_id": service_id,
        "probe_id": probe_id,
        "probe_args": list(probe_args),
        "trigger_delay_s": trigger_delay_s,
    }
    if probe_response is not None:
        record["stdout_json"] = probe_response
    else:
        record["stdout_json_error"] = "probe_response_missing"
    return record
