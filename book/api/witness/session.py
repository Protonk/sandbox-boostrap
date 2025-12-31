"""
Session helpers for PolicyWitness `xpc session` (control plane).

`policy-witness xpc session` exposes a JSONL stdin/stdout protocol intended
for deterministic attach workflows (lldb/dtrace/frida) and multi-probe runs
under a stable service process.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Sequence

from book.api import path_utils
from book.api.witness.observer import (
    OBSERVER_LAST,
    extract_correlation_id,
    extract_process_name,
    extract_service_pid,
    observer_status,
    run_sandbox_log_observer,
    should_run_observer,
)
from book.api.witness.paths import REPO_ROOT, WITNESS_CLI
from book.api.witness.protocol import (
    WaitSpec,
    normalize_wait_spec,
    parse_wait_spec,
    trigger_wait_path,
)


def _read_lines(stream, sink: List[str]) -> None:
    for line in iter(stream.readline, ""):
        sink.append(line)


_STREAM_BUFFERS: Dict[int, str] = {}


def _read_nonblocking(stream, fd: int, size: int = 4096) -> str:
    try:
        os.set_blocking(fd, False)
        try:
            return stream.read(size) or ""
        finally:
            os.set_blocking(fd, True)
    except (BlockingIOError, OSError, ValueError):
        return ""


def _readline_with_timeout(stream, timeout_s: float) -> Optional[str]:
    key = id(stream)
    buf = _STREAM_BUFFERS.get(key, "")

    def pop_line() -> Optional[str]:
        nonlocal buf
        line, sep, rest = buf.partition("\n")
        if not sep:
            return None
        buf = rest
        return line + sep

    line = pop_line()
    if line is not None:
        _STREAM_BUFFERS[key] = buf
        return line

    try:
        fd = stream.fileno()
    except Exception:
        return None

    deadline = time.monotonic() + max(timeout_s, 0.0)
    while time.monotonic() <= deadline:
        chunk = _read_nonblocking(stream, fd)
        if chunk:
            buf += chunk
            line = pop_line()
            if line is not None:
                _STREAM_BUFFERS[key] = buf
                return line
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            rlist, _, _ = select.select([stream], [], [], min(0.2, remaining))
        except Exception:
            time.sleep(min(0.2, remaining))
            continue
        if not rlist:
            continue

    _STREAM_BUFFERS[key] = buf
    return None


class XpcSession:
    """
    Live wrapper around `policy-witness xpc session`.

    - Call `start()` or use as a context manager.
    - Use `run_probe()` repeatedly.
    - If `wait_spec` is set, call `trigger_wait()` to satisfy the barrier.
    """

    def __init__(
        self,
        *,
        profile_id: str,
        plan_id: str,
        correlation_id: Optional[str] = None,
        wait_spec: Optional[str | WaitSpec] = None,
        wait_timeout_ms: Optional[int] = None,
        wait_interval_ms: Optional[int] = None,
        xpc_timeout_ms: Optional[int] = None,
        cwd: Path = REPO_ROOT,
    ) -> None:
        if not profile_id:
            raise ValueError("profile_id is required for xpc session")
        self.profile_id = profile_id
        self.plan_id = plan_id
        self.correlation_id = correlation_id
        self.wait_spec = normalize_wait_spec(wait_spec)
        self.wait_timeout_ms = wait_timeout_ms
        self.wait_interval_ms = wait_interval_ms
        self.xpc_timeout_ms = xpc_timeout_ms
        self.cwd = cwd

        self.proc: Optional[subprocess.Popen] = None
        self.stdout_lines: List[str] = []
        self.stderr_lines: List[str] = []
        self.stdout_jsonl: List[Dict[str, object]] = []
        self.session_ready: Optional[Dict[str, object]] = None
        self.wait_ready: Optional[Dict[str, object]] = None
        self._stderr_thread: Optional[threading.Thread] = None

        self.started_at_unix_s: Optional[float] = None
        self.closed_at_unix_s: Optional[float] = None
        self.exit_code: Optional[int] = None
        self.last_error: Optional[Dict[str, object]] = None

    def _set_last_error(self, code: str, details: Dict[str, object]) -> None:
        self.last_error = {"code": code, **details}

    def _proc_state(self) -> str:
        if self.proc is None:
            return "not_started"
        if self.proc.poll() is None:
            return "running"
        return f"exit:{self.proc.returncode}"

    def _build_cmd(self) -> List[str]:
        cmd = [str(WITNESS_CLI), "xpc", "session", "--plan-id", self.plan_id]
        if self.correlation_id:
            cmd += ["--correlation-id", self.correlation_id]
        if self.wait_spec:
            cmd += ["--wait", self.wait_spec]
        if self.wait_timeout_ms is not None:
            cmd += ["--wait-timeout-ms", str(self.wait_timeout_ms)]
        if self.wait_interval_ms is not None:
            cmd += ["--wait-interval-ms", str(self.wait_interval_ms)]
        if self.xpc_timeout_ms is not None:
            cmd += ["--xpc-timeout-ms", str(self.xpc_timeout_ms)]
        cmd += ["--profile", self.profile_id]
        return cmd

    def command(self) -> List[str]:
        return path_utils.relativize_command(self._build_cmd(), REPO_ROOT)

    def _ingest_json(self, obj: Dict[str, object]) -> None:
        self.stdout_jsonl.append(obj)
        if obj.get("kind") != "xpc_session_event":
            return
        data = obj.get("data")
        if not isinstance(data, dict):
            return
        event = data.get("event")
        if event == "session_ready":
            self.session_ready = obj
        elif event == "wait_ready":
            self.wait_ready = obj

    def _ingest_line(self, line: str) -> Optional[Dict[str, object]]:
        self.stdout_lines.append(line)
        stripped = line.strip()
        if not stripped:
            return None
        try:
            obj = json.loads(stripped)
        except Exception:
            return None
        if isinstance(obj, dict):
            self._ingest_json(obj)
            return obj
        return None

    def start(self, *, ready_timeout_s: float = 15.0) -> None:
        if self.proc is not None:
            return
        cmd = self._build_cmd()
        self.started_at_unix_s = time.time()
        self.proc = subprocess.Popen(
            cmd,
            cwd=str(self.cwd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert self.proc.stdin and self.proc.stdout and self.proc.stderr

        self._stderr_thread = threading.Thread(target=_read_lines, args=(self.proc.stderr, self.stderr_lines))
        self._stderr_thread.start()

        want_wait_ready = self.wait_spec is not None
        deadline = time.monotonic() + max(ready_timeout_s, 0.0)
        while time.monotonic() <= deadline:
            line = _readline_with_timeout(self.proc.stdout, timeout_s=0.2)
            if line is None:
                if self.proc.poll() is not None:
                    break
                continue
            self._ingest_line(line)
            if self.session_ready is not None and (not want_wait_ready or self.wait_ready is not None):
                return

        stderr_preview = "".join(self.stderr_lines).strip()
        stdout_preview = "".join(self.stdout_lines).strip()
        state = "timeout" if self.proc.poll() is None else f"exit:{self.proc.returncode}"
        error = {
            "state": state,
            "command": self.command(),
            "ready_timeout_s": ready_timeout_s,
            "wait_spec": self.wait_spec,
            "wait_timeout_ms": self.wait_timeout_ms,
            "wait_interval_ms": self.wait_interval_ms,
            "xpc_timeout_ms": self.xpc_timeout_ms,
            "stdout": stdout_preview,
            "stderr": stderr_preview,
        }
        self._set_last_error("xpc_session_not_ready", error)
        raise RuntimeError("xpc_session_not_ready", error)

    def _ensure_live(self) -> subprocess.Popen:
        if self.proc is None:
            raise RuntimeError("session_not_started")
        if self.proc.poll() is not None:
            raise RuntimeError(f"session_exited:{self.proc.returncode}")
        return self.proc

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def pid(self) -> Optional[int]:
        if not self.session_ready or not isinstance(self.session_ready.get("data"), dict):
            return None
        value = self.session_ready["data"].get("pid")
        return value if isinstance(value, int) else None

    def service_name(self) -> Optional[str]:
        if not self.session_ready or not isinstance(self.session_ready.get("data"), dict):
            return None
        data = self.session_ready["data"]
        for key in ("service_name", "process_name", "service"):
            value = data.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    def wait_path(self) -> Optional[str]:
        for source in (self.wait_ready, self.session_ready):
            if source and isinstance(source.get("data"), dict):
                value = source["data"].get("wait_path")
                if isinstance(value, str) and value:
                    return value
        _, path = parse_wait_spec(self.wait_spec)
        return path if path else None

    def wait_mode(self) -> Optional[str]:
        for source in (self.wait_ready, self.session_ready):
            if source and isinstance(source.get("data"), dict):
                value = source["data"].get("wait_mode")
                if isinstance(value, str) and value:
                    return value
        mode, _ = parse_wait_spec(self.wait_spec)
        return mode

    def trigger_wait(self, *, nonblocking: bool = False, timeout_s: float = 2.0) -> Optional[str]:
        wait_path = self.wait_path()
        wait_mode = self.wait_mode()
        if wait_path is None or wait_mode is None:
            return "no_wait_configured"
        return trigger_wait_path(
            wait_path=wait_path,
            wait_mode=wait_mode,
            nonblocking=nonblocking,
            timeout_s=timeout_s,
        )

    def read_jsonl(self, *, timeout_s: float = 0.2) -> Optional[Dict[str, object]]:
        if self.proc is None or self.proc.stdout is None:
            raise RuntimeError("session_not_started")
        line = _readline_with_timeout(self.proc.stdout, timeout_s=timeout_s)
        if line is None:
            return None
        return self._ingest_line(line)

    def poll(self) -> Optional[Dict[str, object]]:
        return self.read_jsonl(timeout_s=0.0)

    def iter_events(self, *, timeout_s: float = 5.0) -> Iterator[Dict[str, object]]:
        proc = self._ensure_live()
        deadline = time.monotonic() + max(timeout_s, 0.0)
        while time.monotonic() <= deadline:
            obj = self.read_jsonl(timeout_s=0.2)
            if obj is None:
                if proc.poll() is not None:
                    return
                continue
            yield obj

    def watch_events(
        self,
        *,
        timeout_s: float = 5.0,
        on_event: Callable[[Dict[str, object]], None],
    ) -> List[Dict[str, object]]:
        events: List[Dict[str, object]] = []
        for obj in self.iter_events(timeout_s=timeout_s):
            events.append(obj)
            on_event(obj)
        return events

    def next_event(
        self,
        *,
        kind: Optional[str] = None,
        event: Optional[str] = None,
        timeout_s: float = 5.0,
    ) -> Optional[Dict[str, object]]:
        proc = self._ensure_live()
        deadline = time.monotonic() + max(timeout_s, 0.0)
        while time.monotonic() <= deadline:
            obj = self.read_jsonl(timeout_s=0.2)
            if obj is None:
                if proc.poll() is not None:
                    raise RuntimeError(f"session_exited:{proc.returncode}")
                continue
            if kind and obj.get("kind") != kind:
                continue
            if event:
                data = obj.get("data")
                if not isinstance(data, dict) or data.get("event") != event:
                    continue
            return obj
        return None

    def wait_for_event(self, *, event: str, timeout_s: float = 5.0) -> Optional[Dict[str, object]]:
        return self.next_event(kind="xpc_session_event", event=event, timeout_s=timeout_s)

    def wait_for_trigger_received(self, *, timeout_s: float = 5.0) -> Optional[Dict[str, object]]:
        return self.wait_for_event(event="trigger_received", timeout_s=timeout_s)

    def send_command(self, payload: Dict[str, object]) -> None:
        proc = self._ensure_live()
        assert proc.stdin is not None
        proc.stdin.write(json.dumps(payload) + "\n")
        proc.stdin.flush()

    def run_probe(
        self,
        *,
        probe_id: str,
        argv: Sequence[str] = (),
        timeout_s: float = 25.0,
    ) -> Dict[str, object]:
        self.send_command({"command": "run_probe", "probe_id": probe_id, "argv": list(argv)})
        try:
            response = self.next_event(kind="probe_response", timeout_s=timeout_s)
        except Exception as exc:
            stderr_preview = "".join(self.stderr_lines).strip()
            stdout_preview = "".join(self.stdout_lines).strip()
            error = {
                "state": self._proc_state(),
                "command": self.command(),
                "probe_id": probe_id,
                "argv": list(argv),
                "probe_timeout_s": timeout_s,
                "stdout": stdout_preview,
                "stderr": stderr_preview,
                "error": f"{type(exc).__name__}: {exc}",
            }
            self._set_last_error("probe_response_error", error)
            raise RuntimeError("probe_response_error", error) from exc
        if response is None:
            stderr_preview = "".join(self.stderr_lines).strip()
            stdout_preview = "".join(self.stdout_lines).strip()
            state = "timeout" if self._proc_state() == "running" else self._proc_state()
            error = {
                "state": state,
                "command": self.command(),
                "probe_id": probe_id,
                "argv": list(argv),
                "probe_timeout_s": timeout_s,
                "stdout": stdout_preview,
                "stderr": stderr_preview,
            }
            self._set_last_error("probe_response_missing", error)
            raise RuntimeError("probe_response_missing", error)
        return response

    def capture_observer(
        self,
        *,
        probe_response: Optional[Dict[str, object]],
        log_path: Optional[Path],
        plan_id: Optional[str] = None,
        row_id: Optional[str] = None,
        observer_last: str = OBSERVER_LAST,
        start_s: Optional[float] = None,
        end_s: Optional[float] = None,
    ) -> tuple[Optional[Dict[str, object]], Optional[str]]:
        if log_path is None or not should_run_observer():
            return None, None
        observer_dest = log_path.parent / "observer" / f"{log_path.name}.observer.json"
        observer_log_path = path_utils.to_repo_relative(observer_dest, REPO_ROOT)
        observer_correlation_id = extract_correlation_id(probe_response) or self.correlation_id
        observer = run_sandbox_log_observer(
            pid=extract_service_pid(probe_response),
            process_name=extract_process_name(probe_response),
            dest_path=observer_dest,
            last=observer_last,
            start_s=start_s,
            end_s=end_s,
            plan_id=plan_id or self.plan_id,
            row_id=row_id,
            correlation_id=observer_correlation_id,
        )
        return observer, observer_log_path

    def run_probe_with_observer(
        self,
        *,
        probe_id: str,
        argv: Sequence[str] = (),
        timeout_s: float = 25.0,
        log_path: Optional[Path] = None,
        plan_id: Optional[str] = None,
        row_id: Optional[str] = None,
        observer_last: str = OBSERVER_LAST,
        observer_start_s: Optional[float] = None,
        observer_end_s: Optional[float] = None,
        write_probe_log: bool = True,
        raise_on_error: bool = False,
    ) -> Dict[str, object]:
        probe_started_at_unix_s = time.time()
        probe_response: Optional[Dict[str, object]] = None
        probe_error: Optional[str] = None
        try:
            probe_response = self.run_probe(probe_id=probe_id, argv=argv, timeout_s=timeout_s)
        except Exception as exc:
            probe_error = f"{type(exc).__name__}: {exc}"
            if raise_on_error:
                raise
        probe_finished_at_unix_s = time.time()

        log_write_error = None
        if log_path is not None and write_probe_log and probe_response is not None:
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.write_text(json.dumps(probe_response) + "\n")
            except Exception as exc:
                log_write_error = f"{type(exc).__name__}: {exc}"

        observer_start = observer_start_s if observer_start_s is not None else probe_started_at_unix_s
        observer_end = observer_end_s if observer_end_s is not None else probe_finished_at_unix_s
        observer, observer_log_path = self.capture_observer(
            probe_response=probe_response,
            log_path=log_path,
            plan_id=plan_id,
            row_id=row_id,
            observer_last=observer_last,
            start_s=observer_start,
            end_s=observer_end,
        )

        record: Dict[str, object] = {
            "probe_id": probe_id,
            "probe_args": list(argv),
            "plan_id": plan_id or self.plan_id,
            "row_id": row_id,
            "correlation_id": self.correlation_id,
            "probe_timeout_s": timeout_s,
            "probe_started_at_unix_s": probe_started_at_unix_s,
            "probe_finished_at_unix_s": probe_finished_at_unix_s,
            "duration_s": probe_finished_at_unix_s - probe_started_at_unix_s,
            "log_path": path_utils.to_repo_relative(log_path, REPO_ROOT) if log_path else None,
            "log_write_error": log_write_error,
            "observer": observer,
            "observer_log_path": observer_log_path,
            "observer_status": observer_status(observer),
            "probe_error": probe_error,
        }
        if probe_response is not None:
            record["stdout_json"] = probe_response
        else:
            record["stdout_json_error"] = probe_error or "probe_response_missing"
        return record

    def close(self, *, timeout_s: float = 2.0) -> None:
        if self.proc is None:
            return
        proc = self.proc
        if proc.poll() is None:
            try:
                self.send_command({"command": "close_session"})
            except Exception:
                pass
        drain_deadline = time.monotonic() + 0.5
        while time.monotonic() <= drain_deadline and proc.stdout is not None:
            line = _readline_with_timeout(proc.stdout, timeout_s=0.1)
            if line is None:
                break
            self._ingest_line(line)

        try:
            proc.wait(timeout=timeout_s)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=timeout_s)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=timeout_s)
                except Exception:
                    pass

        self.exit_code = proc.returncode
        self.closed_at_unix_s = time.time()
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=1.0)

        self.proc = None

    def __enter__(self) -> "XpcSession":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def open_session(
    *,
    profile_id: str,
    plan_id: str,
    correlation_id: Optional[str] = None,
    wait_spec: Optional[str | WaitSpec] = None,
    wait_timeout_ms: Optional[int] = None,
    wait_interval_ms: Optional[int] = None,
    xpc_timeout_ms: Optional[int] = None,
    ready_timeout_s: float = 15.0,
    cwd: Path = REPO_ROOT,
) -> XpcSession:
    session = XpcSession(
        profile_id=profile_id,
        plan_id=plan_id,
        correlation_id=correlation_id,
        wait_spec=wait_spec,
        wait_timeout_ms=wait_timeout_ms,
        wait_interval_ms=wait_interval_ms,
        xpc_timeout_ms=xpc_timeout_ms,
        cwd=cwd,
    )
    session.start(ready_timeout_s=ready_timeout_s)
    return session
