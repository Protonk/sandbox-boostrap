"""
Session helpers for EntitlementJail `xpc session` (v2 control plane).

`entitlement-jail xpc session` exposes a JSONL stdin/stdout protocol intended
for deterministic attach workflows (lldb/dtrace/frida) and multi-probe runs
under a stable service process.
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
from typing import Dict, List, Optional, Sequence

from book.api import path_utils
from book.api.entitlementjail.paths import EJ, REPO_ROOT


def _read_lines(stream, sink: List[str]) -> None:
    for line in iter(stream.readline, ""):
        sink.append(line)


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


class XpcSession:
    """
    Live wrapper around `entitlement-jail xpc session`.

    - Call `start()` or use as a context manager.
    - Use `run_probe()` repeatedly.
    - If `wait_spec` is set, call `trigger_wait()` to satisfy the barrier.
    """

    def __init__(
        self,
        *,
        profile_id: Optional[str] = None,
        service_id: Optional[str] = None,
        plan_id: str,
        correlation_id: Optional[str] = None,
        ack_risk: Optional[str] = None,
        wait_spec: Optional[str] = None,
        wait_timeout_ms: Optional[int] = None,
        wait_interval_ms: Optional[int] = None,
        xpc_timeout_ms: Optional[int] = None,
        cwd: Path = REPO_ROOT,
    ) -> None:
        if (profile_id is None) == (service_id is None):
            raise ValueError("Provide exactly one of profile_id or service_id")
        self.profile_id = profile_id
        self.service_id = service_id
        self.plan_id = plan_id
        self.correlation_id = correlation_id
        self.ack_risk = ack_risk
        self.wait_spec = wait_spec
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

    def _build_cmd(self) -> List[str]:
        cmd = [str(EJ), "xpc", "session", "--plan-id", self.plan_id]
        if self.ack_risk:
            cmd += ["--ack-risk", self.ack_risk]
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
        if self.profile_id is not None:
            cmd += ["--profile", self.profile_id]
        else:
            cmd += ["--service", self.service_id]
        return cmd

    def command(self) -> List[str]:
        return path_utils.relativize_command(self._build_cmd(), REPO_ROOT)

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
            self.stdout_lines.append(line)
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            self.stdout_jsonl.append(obj)
            if obj.get("kind") == "xpc_session_event":
                data = obj.get("data")
                if isinstance(data, dict):
                    event = data.get("event")
                    if event == "session_ready":
                        self.session_ready = obj
                    elif event == "wait_ready":
                        self.wait_ready = obj
            if self.session_ready is not None and (not want_wait_ready or self.wait_ready is not None):
                return

        stderr_preview = "".join(self.stderr_lines).strip()
        stdout_preview = "".join(self.stdout_lines).strip()
        state = "timeout" if self.proc.poll() is None else f"exit:{self.proc.returncode}"
        raise RuntimeError(
            "xpc_session_not_ready",
            {
                "state": state,
                "command": self.command(),
                "stdout": stdout_preview,
                "stderr": stderr_preview,
            },
        )

    def _ensure_live(self) -> subprocess.Popen:
        if self.proc is None:
            raise RuntimeError("session_not_started")
        if self.proc.poll() is not None:
            raise RuntimeError(f"session_exited:{self.proc.returncode}")
        return self.proc

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
        if not self.wait_ready or not isinstance(self.wait_ready.get("data"), dict):
            return None
        value = self.wait_ready["data"].get("wait_path")
        return value if isinstance(value, str) and value else None

    def wait_mode(self) -> Optional[str]:
        if self.wait_spec:
            if self.wait_spec.startswith("fifo:"):
                return "fifo"
            if self.wait_spec.startswith("exists:"):
                return "exists"
        path = self.wait_path()
        if not path:
            return None
        return "fifo" if path.endswith(".fifo") else "exists"

    def trigger_wait(self, *, nonblocking: bool = False, timeout_s: float = 2.0) -> Optional[str]:
        wait_path = self.wait_path()
        wait_mode = self.wait_mode()
        if wait_path is None or wait_mode is None:
            return "no_wait_configured"
        path = Path(wait_path)
        if wait_mode == "fifo":
            return _trigger_fifo(path, nonblocking=nonblocking, timeout_s=timeout_s)
        return _trigger_exists(path)

    def wait_for_event(self, *, event: str, timeout_s: float = 5.0) -> Optional[Dict[str, object]]:
        proc = self._ensure_live()
        assert proc.stdout is not None
        deadline = time.monotonic() + max(timeout_s, 0.0)
        while time.monotonic() <= deadline:
            line = _readline_with_timeout(proc.stdout, timeout_s=0.2)
            if line is None:
                if proc.poll() is not None:
                    raise RuntimeError(f"session_exited:{proc.returncode}")
                continue
            self.stdout_lines.append(line)
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            self.stdout_jsonl.append(obj)
            if obj.get("kind") != "xpc_session_event":
                continue
            data = obj.get("data")
            if not isinstance(data, dict):
                continue
            if data.get("event") == event:
                return obj
        return None

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
        proc = self._ensure_live()
        self.send_command({"command": "run_probe", "probe_id": probe_id, "argv": list(argv)})

        assert proc.stdout is not None
        deadline = time.monotonic() + max(timeout_s, 0.0)
        while time.monotonic() <= deadline:
            line = _readline_with_timeout(proc.stdout, timeout_s=0.2)
            if line is None:
                if proc.poll() is not None:
                    break
                continue
            self.stdout_lines.append(line)
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            self.stdout_jsonl.append(obj)
            if obj.get("kind") == "probe_response":
                return obj

        stderr_preview = "".join(self.stderr_lines).strip()
        stdout_preview = "".join(self.stdout_lines).strip()
        state = "timeout" if proc.poll() is None else f"exit:{proc.returncode}"
        raise RuntimeError(
            "probe_response_missing",
            {
                "state": state,
                "command": self.command(),
                "probe_id": probe_id,
                "argv": list(argv),
                "stdout": stdout_preview,
                "stderr": stderr_preview,
            },
        )

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
            self.stdout_lines.append(line)
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except Exception:
                continue
            if isinstance(obj, dict):
                self.stdout_jsonl.append(obj)

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
