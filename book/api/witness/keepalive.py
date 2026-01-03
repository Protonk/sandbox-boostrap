"""Keepalive daemon with a control socket and JSONL events."""

from __future__ import annotations

import argparse
import json
import os
import select
import socket
import socketserver
import stat
import subprocess
import sys
import sysconfig
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from book.api import path_utils
from book.api.profile.identity import baseline_world_id
from book.api.witness import session as witness_session
from book.api.witness.paths import (
    REPO_ROOT,
    WITNESS_CLI,
    WITNESS_FRIDA_ATTACH_HELPER,
    WITNESS_HOLD_OPEN,
    WITNESS_KEEPALIVE_OUT,
)
from book.api.witness.protocol import normalize_wait_spec, trigger_wait_path

KEEPALIVE_PROTOCOL_VERSION = 1
KEEPALIVE_EVENT_KIND = "keepalive_event"


class KeepaliveError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        kind: str = "request_error",
        limits: Optional[str] = None,
        details: Optional[Dict[str, object]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.kind = kind
        self.limits = limits
        self.details = details or {}

    def to_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "code": self.code,
            "kind": self.kind,
            "message": self.message,
        }
        if self.limits:
            payload["limits"] = self.limits
        if self.details:
            payload["details"] = self.details
        return payload


def _now_unix_s() -> float:
    return time.time()


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False
    return True


def _read_lines(stream, sink: List[str]) -> None:
    for line in iter(stream.readline, ""):
        sink.append(line)


def _readline_with_timeout(stream, timeout_s: float) -> Optional[str]:
    try:
        fd = stream.fileno()
    except Exception:
        return None
    deadline = time.monotonic() + max(timeout_s, 0.0)
    while time.monotonic() <= deadline:
        remaining = deadline - time.monotonic()
        try:
            rlist, _, _ = select.select([fd], [], [], min(0.2, remaining))
        except Exception:
            time.sleep(min(0.2, remaining))
            continue
        if not rlist:
            continue
        line = stream.readline()
        if not line:
            return None
        return line
    return None


def _read_json_until_ready(
    proc: subprocess.Popen[str],
    *,
    ready_timeout_s: float,
    stdout_lines: List[str],
) -> Dict[str, object]:
    assert proc.stdout is not None
    deadline = time.monotonic() + max(ready_timeout_s, 0.0)
    while time.monotonic() <= deadline:
        line = _readline_with_timeout(proc.stdout, timeout_s=0.2)
        if line is None:
            if proc.poll() is not None:
                break
            continue
        stdout_lines.append(line)
        payload = line.strip()
        if not payload:
            continue
        try:
            obj = json.loads(payload)
        except Exception:
            continue
        if isinstance(obj, dict) and obj.get("kind") == "hold_open_ready":
            return obj
    raise KeepaliveError(
        "hold_open_not_ready",
        "hold_open did not report ready",
        details={"stdout": "".join(stdout_lines).strip()},
    )


def _read_json_until_kind(
    proc: subprocess.Popen[str],
    *,
    kind: str,
    ready_timeout_s: float,
    stdout_lines: List[str],
    error_kinds: Sequence[str] = ("attach_error", "error"),
) -> Dict[str, object]:
    assert proc.stdout is not None
    deadline = time.monotonic() + max(ready_timeout_s, 0.0)
    while time.monotonic() <= deadline:
        line = _readline_with_timeout(proc.stdout, timeout_s=0.2)
        if line is None:
            if proc.poll() is not None:
                break
            continue
        stdout_lines.append(line)
        payload = line.strip()
        if not payload:
            continue
        try:
            obj = json.loads(payload)
        except Exception:
            continue
        if isinstance(obj, dict) and obj.get("kind") == kind:
            return obj
        if isinstance(obj, dict) and obj.get("kind") in error_kinds:
            raise KeepaliveError(
                "frida_helper_error",
                str(obj.get("error") or "helper error"),
                details={"stdout": "".join(stdout_lines).strip()},
            )
    raise KeepaliveError(
        "helper_not_ready",
        "frida helper did not report ready",
        details={"stdout": "".join(stdout_lines).strip()},
    )


def _helper_python_paths(repo_root: Path) -> List[str]:
    paths = [str(repo_root)]
    sys_paths = sysconfig.get_paths()
    for key in ("purelib", "platlib"):
        value = sys_paths.get(key)
        if isinstance(value, str) and value and value not in paths:
            paths.append(value)
    return paths


def _ensure_socket_path(path: Path) -> None:
    if path.exists():
        try:
            if stat.S_ISSOCK(path.stat().st_mode):
                path.unlink()
                return
        except Exception as exc:
            raise KeepaliveError("socket_cleanup_failed", f"unable to clean socket: {exc}") from exc
        raise KeepaliveError("socket_path_conflict", f"path exists and is not a socket: {path}")


def _normalize_command(parts: Sequence[str], repo_root: Path) -> List[str]:
    normalized: List[str] = []
    for part in parts:
        if not isinstance(part, str):
            raise KeepaliveError("bad_command", f"command part is not a string: {part!r}")
        if part.startswith("/") or part.startswith(".") or "/" in part:
            normalized.append(str(path_utils.ensure_absolute(part, repo_root)))
        else:
            normalized.append(part)
    return normalized


def _maybe_relativize(path: Optional[str], repo_root: Path) -> Optional[str]:
    if not path:
        return None
    return path_utils.to_repo_relative(path, repo_root)


@dataclass(frozen=True)
class KeepaliveConfig:
    control_path: Path
    events_path: Path
    stage: str
    lane: str
    world_id: str
    repo_root: Path
    run_id: str

    @classmethod
    def default(
        cls,
        *,
        stage: str = "operation",
        lane: str = "oracle",
        repo_root: Optional[Path] = None,
    ) -> "KeepaliveConfig":
        root = repo_root or REPO_ROOT
        run_id = uuid.uuid4().hex
        run_dir = WITNESS_KEEPALIVE_OUT / run_id
        socket_id = run_id[:8]
        return cls(
            control_path=WITNESS_KEEPALIVE_OUT / f"keepalive-{socket_id}.sock",
            events_path=run_dir / "events.jsonl",
            stage=stage,
            lane=lane,
            world_id=baseline_world_id(root),
            repo_root=root,
            run_id=run_id,
        )


@dataclass
class TargetState:
    target_id: str
    mode: str
    provider: str
    pid: Optional[int]
    command: Optional[List[str]]
    wait_mode: Optional[str]
    wait_path: Optional[str]
    started_at_unix_s: float
    ready_at_unix_s: Optional[float]
    status: str
    service_name: Optional[str] = None
    session: Optional[witness_session.XpcSession] = None
    proc: Optional[subprocess.Popen[str]] = None
    lease_deadline_s: Optional[float] = None

    def to_record(self, *, repo_root: Path, stage: str, lane: str) -> Dict[str, object]:
        return {
            "target_id": self.target_id,
            "mode": self.mode,
            "provider": self.provider,
            "pid": self.pid,
            "command": path_utils.relativize_command(self.command, repo_root) if self.command else None,
            "wait_mode": self.wait_mode,
            "wait_path": _maybe_relativize(self.wait_path, repo_root),
            "service_name": self.service_name,
            "started_at_unix_s": self.started_at_unix_s,
            "ready_at_unix_s": self.ready_at_unix_s,
            "status": self.status,
            "stage": stage,
            "lane": lane,
        }


@dataclass
class HookState:
    hook_id: str
    kind: str
    target_id: str
    status: str
    started_at_unix_s: float
    error: Optional[str] = None
    events_path: Optional[str] = None
    meta_path: Optional[str] = None
    gate_release: bool = False
    capture: Optional[object] = None
    proc: Optional[subprocess.Popen[str]] = None
    helper_path: Optional[str] = None
    helper_pid: Optional[int] = None

    def to_record(self, *, repo_root: Path, stage: str, lane: str) -> Dict[str, object]:
        return {
            "hook_id": self.hook_id,
            "kind": self.kind,
            "target_id": self.target_id,
            "status": self.status,
            "error": self.error,
            "events_path": _maybe_relativize(self.events_path, repo_root),
            "meta_path": _maybe_relativize(self.meta_path, repo_root),
            "gate_release": self.gate_release,
            "helper_path": _maybe_relativize(self.helper_path, repo_root),
            "helper_pid": self.helper_pid,
            "started_at_unix_s": self.started_at_unix_s,
            "stage": stage,
            "lane": lane,
        }


class KeepaliveEventWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = self.path.open("a", encoding="utf-8")
        self._lock = threading.Lock()

    def emit(self, payload: Dict[str, object]) -> None:
        with self._lock:
            self._fp.write(json.dumps(payload) + "\n")
            self._fp.flush()

    def close(self) -> None:
        with self._lock:
            self._fp.close()


class _KeepaliveServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


class _KeepaliveHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server = self.server
        keepalive: KeepaliveDaemon = server.keepalive  # type: ignore[attr-defined]
        for raw in self.rfile:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except Exception as exc:
                response = keepalive._error_response(
                    request_id=None,
                    error=KeepaliveError("bad_json", f"invalid json: {exc}"),
                )
            else:
                response = keepalive.handle_request(request)
            self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))
            self.wfile.flush()


class KeepaliveDaemon:
    def __init__(self, config: KeepaliveConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        self.targets: Dict[str, TargetState] = {}
        self.hooks: Dict[str, HookState] = {}
        self._events = KeepaliveEventWriter(self.config.events_path)
        self._stop = threading.Event()
        self._server: Optional[_KeepaliveServer] = None
        self._lease_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        _ensure_socket_path(self.config.control_path)
        self.config.control_path.parent.mkdir(parents=True, exist_ok=True)
        self._server = _KeepaliveServer(str(self.config.control_path), _KeepaliveHandler)
        self._server.keepalive = self
        self._lease_thread = threading.Thread(target=self._lease_loop, name="keepalive-lease", daemon=True)
        self._lease_thread.start()
        self.emit_event(
            "daemon_ready",
            {
                "control_path": path_utils.to_repo_relative(self.config.control_path, self.config.repo_root),
                "events_path": path_utils.to_repo_relative(self.config.events_path, self.config.repo_root),
            },
        )

    def serve_forever(self) -> None:
        if self._server is None:
            raise RuntimeError("keepalive server not started")
        self._server.serve_forever(poll_interval=0.2)

    def shutdown(self) -> None:
        self._stop.set()
        self._release_all(reason="shutdown")
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        self._events.close()
        if self.config.control_path.exists():
            try:
                self.config.control_path.unlink()
            except Exception:
                pass

    def emit_event(self, event: str, payload: Dict[str, object]) -> None:
        base = {
            "kind": KEEPALIVE_EVENT_KIND,
            "schema_version": KEEPALIVE_PROTOCOL_VERSION,
            "event": event,
            "world_id": self.config.world_id,
            "stage": self.config.stage,
            "lane": self.config.lane,
            "run_id": self.config.run_id,
            "t_unix_s": _now_unix_s(),
        }
        base.update(payload)
        self._events.emit(base)

    def handle_request(self, request: Dict[str, object]) -> Dict[str, object]:
        request_id = request.get("id")
        try:
            result = self._dispatch(request)
        except KeepaliveError as exc:
            return self._error_response(request_id=request_id, error=exc)
        except Exception as exc:
            return self._error_response(
                request_id=request_id,
                error=KeepaliveError("internal_error", f"{type(exc).__name__}: {exc}"),
            )
        return {
            "id": request_id,
            "ok": True,
            "result": result,
            "meta": {
                "world_id": self.config.world_id,
                "stage": self.config.stage,
                "lane": self.config.lane,
                "run_id": self.config.run_id,
                "t_unix_s": _now_unix_s(),
            },
        }

    def _error_response(self, *, request_id: Optional[str], error: KeepaliveError) -> Dict[str, object]:
        return {
            "id": request_id,
            "ok": False,
            "error": error.to_dict(),
            "meta": {
                "world_id": self.config.world_id,
                "stage": self.config.stage,
                "lane": self.config.lane,
                "run_id": self.config.run_id,
                "t_unix_s": _now_unix_s(),
            },
        }

    def _dispatch(self, request: Dict[str, object]) -> Dict[str, object]:
        if not isinstance(request, dict):
            raise KeepaliveError("bad_request", "request must be a JSON object")
        request_type = request.get("type")
        if not isinstance(request_type, str):
            raise KeepaliveError("bad_request", "missing request type")
        params = request.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise KeepaliveError("bad_request", "params must be a JSON object")
        if request_type == "hello":
            return self._cmd_hello()
        if request_type == "start_target":
            return self._cmd_start_target(params)
        if request_type == "attach_target":
            params = dict(params)
            params.setdefault("mode", "attach")
            return self._cmd_start_target(params)
        if request_type == "hook_target":
            return self._cmd_hook_target(params)
        if request_type == "hook_finalize":
            return self._cmd_hook_finalize(params)
        if request_type == "status":
            return self._cmd_status(params)
        if request_type == "renew_lease":
            return self._cmd_renew_lease(params)
        if request_type == "release":
            return self._cmd_release(params)
        if request_type == "terminate":
            return self._cmd_terminate()
        if request_type == "subscribe":
            return self._cmd_subscribe()
        raise KeepaliveError("unknown_request", f"unknown request type: {request_type}")

    def _cmd_hello(self) -> Dict[str, object]:
        return {
            "version": KEEPALIVE_PROTOCOL_VERSION,
            "world_id": self.config.world_id,
            "stage": self.config.stage,
            "lane": self.config.lane,
            "run_id": self.config.run_id,
            "control_path": path_utils.to_repo_relative(self.config.control_path, self.config.repo_root),
            "events_path": path_utils.to_repo_relative(self.config.events_path, self.config.repo_root),
            "capabilities": {
                "policywitness": WITNESS_CLI.exists(),
                "hold_open": WITNESS_HOLD_OPEN.exists(),
                "frida": _frida_available(),
                "frida_helper": WITNESS_FRIDA_ATTACH_HELPER.exists(),
            },
        }

    def _cmd_start_target(self, params: Dict[str, object]) -> Dict[str, object]:
        mode = params.get("mode")
        if not isinstance(mode, str):
            raise KeepaliveError("bad_request", "missing target mode")
        target_id = params.get("target_id")
        if not isinstance(target_id, str) or not target_id:
            target_id = f"t-{uuid.uuid4().hex}"
        provider_override = params.get("provider")
        if provider_override is not None and not isinstance(provider_override, str):
            raise KeepaliveError("bad_request", "provider must be a string")
        with self._lock:
            if target_id in self.targets:
                raise KeepaliveError("target_exists", f"target already exists: {target_id}")
        if mode in {"policywitness", "policywitness_session"}:
            target = self._start_policywitness(target_id, params)
        elif mode == "spawn":
            target = self._start_spawn(target_id, params, provider_override)
        elif mode == "attach":
            target = self._start_attach(target_id, params)
        else:
            raise KeepaliveError("bad_request", f"unsupported target mode: {mode}")
        lease = params.get("lease")
        if isinstance(lease, dict):
            ttl = lease.get("ttl_seconds")
            if isinstance(ttl, (int, float)) and ttl > 0:
                target.lease_deadline_s = time.monotonic() + float(ttl)
        with self._lock:
            self.targets[target_id] = target
        self.emit_event(
            "target_ready",
            {
                "target_id": target_id,
                "target": target.to_record(
                    repo_root=self.config.repo_root, stage=self.config.stage, lane=self.config.lane
                ),
            },
        )
        return {
            "target": target.to_record(repo_root=self.config.repo_root, stage=self.config.stage, lane=self.config.lane),
        }

    def _start_policywitness(self, target_id: str, params: Dict[str, object]) -> TargetState:
        if not WITNESS_CLI.exists():
            raise KeepaliveError("policywitness_missing", "PolicyWitness CLI not found")
        profile_id = params.get("profile_id")
        if not isinstance(profile_id, str) or not profile_id:
            raise KeepaliveError("bad_request", "policywitness target requires profile_id")
        plan_id = params.get("plan_id", "keepalive:session")
        correlation_id = params.get("correlation_id")
        wait_spec = normalize_wait_spec(params.get("wait_spec"))
        ready_timeout_s = params.get("ready_timeout_s", 15.0)
        wait_timeout_ms = params.get("wait_timeout_ms")
        wait_interval_ms = params.get("wait_interval_ms")
        xpc_timeout_ms = params.get("xpc_timeout_ms")
        session = witness_session.XpcSession(
            profile_id=profile_id,
            plan_id=str(plan_id),
            correlation_id=correlation_id if isinstance(correlation_id, str) else None,
            wait_spec=wait_spec,
            wait_timeout_ms=wait_timeout_ms if isinstance(wait_timeout_ms, int) else None,
            wait_interval_ms=wait_interval_ms if isinstance(wait_interval_ms, int) else None,
            xpc_timeout_ms=xpc_timeout_ms if isinstance(xpc_timeout_ms, int) else None,
            cwd=self.config.repo_root,
        )
        try:
            session.start(ready_timeout_s=float(ready_timeout_s))
        except Exception as exc:
            details = getattr(exc, "args", None)
            raise KeepaliveError(
                "policywitness_start_failed",
                f"policywitness session failed: {type(exc).__name__}: {exc}",
                details={"details": details},
            ) from exc
        return TargetState(
            target_id=target_id,
            mode="policywitness",
            provider="policywitness",
            pid=session.pid(),
            command=session.command(),
            wait_mode=session.wait_mode(),
            wait_path=session.wait_path(),
            started_at_unix_s=session.started_at_unix_s or _now_unix_s(),
            ready_at_unix_s=_now_unix_s(),
            status="ready",
            service_name=session.service_name(),
            session=session,
        )

    def _start_spawn(self, target_id: str, params: Dict[str, object], provider_override: Optional[str]) -> TargetState:
        wait_spec = normalize_wait_spec(params.get("wait_spec"))
        command_prefix = params.get("command_prefix") or []
        if not isinstance(command_prefix, list):
            raise KeepaliveError("bad_request", "command_prefix must be a list")
        command = params.get("command")
        if command is None:
            hold_open_path = params.get("hold_open_path") or str(WITNESS_HOLD_OPEN)
            command = [str(hold_open_path)]
            if wait_spec:
                command += ["--wait", wait_spec]
            max_seconds = params.get("max_seconds")
            if max_seconds is not None:
                command += ["--max-seconds", str(max_seconds)]
        if not isinstance(command, list) or not command:
            raise KeepaliveError("bad_request", "spawn target requires command list")
        cmd = _normalize_command(command_prefix, self.config.repo_root) + _normalize_command(command, self.config.repo_root)
        proc = subprocess.Popen(
            cmd,
            cwd=str(self.config.repo_root),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        stdout_lines: List[str] = []
        stderr_lines: List[str] = []
        assert proc.stderr is not None
        stderr_thread = threading.Thread(target=_read_lines, args=(proc.stderr, stderr_lines), daemon=True)
        stderr_thread.start()
        ready_timeout_s = params.get("ready_timeout_s", 10.0)
        ready = _read_json_until_ready(proc, ready_timeout_s=float(ready_timeout_s), stdout_lines=stdout_lines)
        wait_mode = ready.get("wait_mode") if isinstance(ready.get("wait_mode"), str) else None
        wait_path = ready.get("wait_path") if isinstance(ready.get("wait_path"), str) else None
        return TargetState(
            target_id=target_id,
            mode="spawn",
            provider=provider_override or "hold_open",
            pid=proc.pid,
            command=cmd,
            wait_mode=wait_mode,
            wait_path=wait_path,
            started_at_unix_s=_now_unix_s(),
            ready_at_unix_s=_now_unix_s(),
            status="ready",
            proc=proc,
        )

    def _start_attach(self, target_id: str, params: Dict[str, object]) -> TargetState:
        pid = params.get("pid")
        if not isinstance(pid, int):
            raise KeepaliveError("bad_request", "attach target requires pid")
        if not _pid_exists(pid):
            raise KeepaliveError("pid_missing", f"pid {pid} does not exist")
        return TargetState(
            target_id=target_id,
            mode="attach",
            provider="pid_lease",
            pid=pid,
            command=None,
            wait_mode=None,
            wait_path=None,
            started_at_unix_s=_now_unix_s(),
            ready_at_unix_s=_now_unix_s(),
            status="ready",
        )

    def _cmd_hook_target(self, params: Dict[str, object]) -> Dict[str, object]:
        target_id = params.get("target_id")
        if not isinstance(target_id, str):
            raise KeepaliveError("bad_request", "hook_target requires target_id")
        kind = params.get("kind")
        if not isinstance(kind, str):
            raise KeepaliveError("bad_request", "hook_target requires kind")
        hook_id = params.get("hook_id")
        if not isinstance(hook_id, str) or not hook_id:
            hook_id = f"h-{uuid.uuid4().hex}"
        with self._lock:
            if target_id not in self.targets:
                raise KeepaliveError("missing_target", f"unknown target: {target_id}")
            if hook_id in self.hooks:
                raise KeepaliveError("hook_exists", f"hook already exists: {hook_id}")
        gate_release = bool(params.get("gate_release"))
        hook = HookState(
            hook_id=hook_id,
            kind=kind,
            target_id=target_id,
            status="starting",
            started_at_unix_s=_now_unix_s(),
            gate_release=gate_release,
        )
        if kind == "frida":
            hook = self._hook_frida(hook, params)
        else:
            hook.status = "ready"
        with self._lock:
            self.hooks[hook_id] = hook
        self.emit_event(
            "hook_ready" if hook.status == "ready" else "hook_error",
            {
                "hook_id": hook_id,
                "hook": hook.to_record(repo_root=self.config.repo_root, stage=self.config.stage, lane=self.config.lane),
            },
        )
        return {
            "hook": hook.to_record(repo_root=self.config.repo_root, stage=self.config.stage, lane=self.config.lane),
        }

    def _cmd_hook_finalize(self, params: Dict[str, object]) -> Dict[str, object]:
        hook_id = params.get("hook_id")
        if not isinstance(hook_id, str):
            raise KeepaliveError("bad_request", "hook_finalize requires hook_id")
        attach_meta = params.get("attach_meta")
        if attach_meta is None:
            attach_meta = {}
        if not isinstance(attach_meta, dict):
            raise KeepaliveError("bad_request", "attach_meta must be an object")
        hook = self.hooks.get(hook_id)
        if hook is None:
            raise KeepaliveError("missing_hook", f"unknown hook: {hook_id}")
        if hook.proc is not None:
            resp = self._helper_request(
                hook, {"type": "finalize", "attach_meta": attach_meta, "world_id": self.config.world_id}
            )
            if resp.get("kind") != "finalize_ok":
                raise KeepaliveError("hook_finalize_failed", str(resp.get("error") or "finalize failed"))
        else:
            capture = hook.capture
            if capture is None or not hasattr(capture, "finalize_meta"):
                raise KeepaliveError("hook_not_ready", f"hook {hook_id} has no capture to finalize")
            try:
                capture.finalize_meta(world_id=self.config.world_id, attach_meta=attach_meta)
            except Exception as exc:
                raise KeepaliveError(
                    "hook_finalize_failed",
                    f"hook finalize failed: {type(exc).__name__}: {exc}",
                ) from exc
        return {
            "hook_id": hook_id,
            "meta_path": _maybe_relativize(hook.meta_path, self.config.repo_root),
        }

    def _hook_frida(self, hook: HookState, params: Dict[str, object]) -> HookState:
        helper_path = params.get("helper_path")
        use_helper = bool(params.get("use_helper") or params.get("helper") or helper_path)
        if use_helper:
            return self._hook_frida_helper(hook, params)
        if not _frida_available():
            hook.status = "error"
            hook.error = "frida_import_error"
            return hook
        target = self.targets.get(hook.target_id)
        if not target or target.pid is None:
            hook.status = "error"
            hook.error = "missing_target_pid"
            return hook
        script_path = params.get("script_path")
        script_inline = params.get("script_inline")
        out_dir = params.get("out_dir")
        if out_dir is None:
            out_dir = (
                WITNESS_KEEPALIVE_OUT
                / self.config.run_id
                / "hooks"
                / hook.hook_id
            )
        out_dir = path_utils.ensure_absolute(out_dir, self.config.repo_root)
        out_dir.mkdir(parents=True, exist_ok=True)
        if script_path is None and script_inline is None:
            hook.status = "error"
            hook.error = "missing_script"
            return hook
        if script_inline is not None and script_path is None:
            script_path = out_dir / "hook.js"
            Path(script_path).write_text(str(script_inline))
        script_path_abs = path_utils.ensure_absolute(str(script_path), self.config.repo_root)
        events_path = out_dir / "events.jsonl"
        meta_path = out_dir / "meta.json"
        try:
            from book.api.frida.capture import FridaCapture
        except Exception as exc:
            hook.status = "error"
            hook.error = f"frida_import_error:{type(exc).__name__}: {exc}"
            return hook
        run_id = params.get("run_id")
        capture = FridaCapture(
            run_id=str(run_id) if isinstance(run_id, str) and run_id else str(uuid.uuid4()),
            pid=target.pid,
            script_path=script_path_abs,
            events_path=events_path,
            meta_path=meta_path,
            config_json=params.get("config_json"),
            config_path=params.get("config_path"),
            config_overlay=params.get("config_overlay") if isinstance(params.get("config_overlay"), dict) else None,
            config_overlay_source={"kind": "keepalive"},
            repo_root=self.config.repo_root,
        )
        error = capture.attach()
        if error:
            hook.status = "error"
            hook.error = error
        else:
            hook.status = "ready"
            hook.events_path = str(events_path)
            hook.meta_path = str(meta_path)
            hook.capture = capture
        return hook

    def _helper_request(self, hook: HookState, payload: Dict[str, object], *, timeout_s: float = 2.0) -> Dict[str, object]:
        proc = hook.proc
        if proc is None or proc.stdin is None or proc.stdout is None:
            raise KeepaliveError("helper_unavailable", "helper process not available")
        if proc.poll() is not None:
            raise KeepaliveError("helper_exited", "helper process exited early")
        proc.stdin.write(json.dumps(payload) + "\n")
        proc.stdin.flush()
        line = _readline_with_timeout(proc.stdout, timeout_s=timeout_s)
        if not line:
            raise KeepaliveError("helper_no_response", "helper did not respond")
        try:
            obj = json.loads(line)
        except Exception as exc:
            raise KeepaliveError("helper_bad_response", f"invalid helper response: {exc}") from exc
        if not isinstance(obj, dict):
            raise KeepaliveError("helper_bad_response", "helper response is not an object")
        return obj

    def _hook_frida_helper(self, hook: HookState, params: Dict[str, object]) -> HookState:
        target = self.targets.get(hook.target_id)
        if not target or target.pid is None:
            hook.status = "error"
            hook.error = "missing_target_pid"
            return hook

        helper_path = params.get("helper_path")
        if not isinstance(helper_path, str) or not helper_path:
            helper_path = str(WITNESS_FRIDA_ATTACH_HELPER)
        helper_path_abs = path_utils.ensure_absolute(helper_path, self.config.repo_root)
        if not helper_path_abs.exists():
            hook.status = "error"
            hook.error = "frida_helper_missing"
            return hook
        if not os.access(helper_path_abs, os.X_OK):
            hook.status = "error"
            hook.error = "frida_helper_not_executable"
            return hook

        script_path = params.get("script_path")
        script_inline = params.get("script_inline")
        out_dir = params.get("out_dir")
        if out_dir is None:
            out_dir = WITNESS_KEEPALIVE_OUT / self.config.run_id / "hooks" / hook.hook_id
        out_dir = path_utils.ensure_absolute(out_dir, self.config.repo_root)
        out_dir.mkdir(parents=True, exist_ok=True)
        if script_path is None and script_inline is None:
            hook.status = "error"
            hook.error = "missing_script"
            return hook
        if script_inline is not None and script_path is None:
            script_path = out_dir / "hook.js"
            Path(script_path).write_text(str(script_inline))
        script_path_abs = path_utils.ensure_absolute(str(script_path), self.config.repo_root)
        events_path = out_dir / "events.jsonl"
        meta_path = out_dir / "meta.json"
        run_id = params.get("run_id")
        run_id_value = str(run_id) if isinstance(run_id, str) and run_id else str(uuid.uuid4())

        helper_python_exec = params.get("helper_python_exec")
        if not isinstance(helper_python_exec, str) or not helper_python_exec:
            helper_python_exec = sys.executable
        helper_python_paths = params.get("helper_python_path")
        if helper_python_paths is None:
            helper_python_paths = _helper_python_paths(self.config.repo_root)
        if not isinstance(helper_python_paths, list):
            hook.status = "error"
            hook.error = "helper_python_path_invalid"
            return hook
        helper_python_paths = [str(p) for p in helper_python_paths if isinstance(p, (str, Path))]

        cmd = [str(helper_path_abs), "--python-exec", helper_python_exec]
        for path in helper_python_paths:
            cmd.extend(["--python-path", path])
        cmd.extend(
            [
                "--",
                "--pid",
                str(target.pid),
                "--script",
                str(script_path_abs),
                "--events",
                str(events_path),
                "--meta",
                str(meta_path),
                "--run-id",
                run_id_value,
                "--repo-root",
                str(self.config.repo_root),
            ]
        )
        config_json = params.get("config_json")
        if isinstance(config_json, str) and config_json:
            cmd.extend(["--config-json", config_json])
        config_path = params.get("config_path")
        if isinstance(config_path, str) and config_path:
            cmd.extend(["--config-path", config_path])
        config_overlay = params.get("config_overlay")
        if isinstance(config_overlay, dict) and config_overlay:
            cmd.extend(["--config-overlay", json.dumps(config_overlay)])

        stdout_lines: List[str] = []
        stderr_lines: List[str] = []
        proc = subprocess.Popen(
            cmd,
            cwd=str(self.config.repo_root),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        hook.helper_path = str(helper_path_abs)
        hook.helper_pid = proc.pid
        assert proc.stderr is not None
        stderr_thread = threading.Thread(target=_read_lines, args=(proc.stderr, stderr_lines), daemon=True)
        stderr_thread.start()
        ready_timeout_s = params.get("ready_timeout_s", 10.0)
        try:
            _read_json_until_kind(
                proc,
                kind="attach_ready",
                ready_timeout_s=float(ready_timeout_s),
                stdout_lines=stdout_lines,
            )
        except KeepaliveError as exc:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2.0)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            hook.status = "error"
            hook.error = f"{exc.code}:{exc.message}"
            return hook

        hook.status = "ready"
        hook.events_path = str(events_path)
        hook.meta_path = str(meta_path)
        hook.proc = proc
        hook.helper_path = str(helper_path_abs)
        hook.helper_pid = proc.pid
        return hook

    def _cmd_status(self, params: Dict[str, object]) -> Dict[str, object]:
        target_id = params.get("target_id")
        hook_id = params.get("hook_id")
        with self._lock:
            targets = self.targets
            hooks = self.hooks
        if target_id:
            target = targets.get(target_id)
            if target is None:
                raise KeepaliveError("missing_target", f"unknown target: {target_id}")
            return {
                "target": self._target_status(target),
            }
        if hook_id:
            hook = hooks.get(hook_id)
            if hook is None:
                raise KeepaliveError("missing_hook", f"unknown hook: {hook_id}")
            return {
                "hook": hook.to_record(repo_root=self.config.repo_root, stage=self.config.stage, lane=self.config.lane),
            }
        return {
            "targets": [
                self._target_status(t) for t in targets.values()
            ],
            "hooks": [
                h.to_record(repo_root=self.config.repo_root, stage=self.config.stage, lane=self.config.lane)
                for h in hooks.values()
            ],
        }

    def _target_status(self, target: TargetState) -> Dict[str, object]:
        alive = False
        if target.session is not None:
            alive = target.session.is_running()
        elif target.proc is not None:
            alive = target.proc.poll() is None
        elif target.pid is not None:
            alive = _pid_exists(target.pid)
        record = target.to_record(repo_root=self.config.repo_root, stage=self.config.stage, lane=self.config.lane)
        record["alive"] = alive
        if target.lease_deadline_s:
            record["lease_remaining_s"] = max(0.0, target.lease_deadline_s - time.monotonic())
        return record

    def _cmd_renew_lease(self, params: Dict[str, object]) -> Dict[str, object]:
        target_id = params.get("target_id")
        if not isinstance(target_id, str):
            raise KeepaliveError("bad_request", "renew_lease requires target_id")
        ttl_seconds = params.get("ttl_seconds")
        extend_seconds = params.get("extend_seconds")
        if ttl_seconds is None and extend_seconds is None:
            raise KeepaliveError("bad_request", "renew_lease requires ttl_seconds or extend_seconds")
        if ttl_seconds is not None and not isinstance(ttl_seconds, (int, float)):
            raise KeepaliveError("bad_request", "ttl_seconds must be a number")
        if extend_seconds is not None and not isinstance(extend_seconds, (int, float)):
            raise KeepaliveError("bad_request", "extend_seconds must be a number")
        with self._lock:
            target = self.targets.get(target_id)
            if target is None:
                raise KeepaliveError("missing_target", f"unknown target: {target_id}")
            if ttl_seconds is not None:
                target.lease_deadline_s = time.monotonic() + float(ttl_seconds)
            else:
                if target.lease_deadline_s is None:
                    target.lease_deadline_s = time.monotonic() + float(extend_seconds)
                else:
                    target.lease_deadline_s += float(extend_seconds)
        return {
            "target_id": target_id,
            "lease_remaining_s": max(0.0, target.lease_deadline_s - time.monotonic()) if target.lease_deadline_s else None,
        }

    def _cmd_release(self, params: Dict[str, object]) -> Dict[str, object]:
        target_id = params.get("target_id")
        if target_id:
            with self._lock:
                target = self.targets.get(target_id)
            if target is None:
                raise KeepaliveError("missing_target", f"unknown target: {target_id}")
            self._release_target(target, reason="release")
            with self._lock:
                self.targets.pop(target_id, None)
            return {"released": target_id}
        self._release_all(reason="release")
        return {"released": "all"}

    def _release_all(self, *, reason: str) -> None:
        with self._lock:
            targets = list(self.targets.values())
            self.targets.clear()
        for target in targets:
            self._release_target(target, reason=reason)

    def _release_target(self, target: TargetState, *, reason: str) -> None:
        blocking_hooks = [
            hook for hook in self.hooks.values() if hook.target_id == target.target_id and hook.gate_release
        ]
        for hook in blocking_hooks:
            if hook.status != "ready":
                raise KeepaliveError(
                    "hook_not_ready",
                    f"hook {hook.hook_id} not ready",
                    limits="release blocked by hook gate",
                )
        self._close_hooks_for_target(target.target_id)
        if target.session is not None:
            if target.wait_path and target.wait_mode:
                target.session.trigger_wait()
            target.session.close()
        if target.proc is not None:
            if target.wait_path and target.wait_mode:
                trigger_wait_path(wait_path=target.wait_path, wait_mode=target.wait_mode, nonblocking=False, timeout_s=2.0)
            if target.proc.poll() is None:
                try:
                    target.proc.terminate()
                    target.proc.wait(timeout=2.0)
                except Exception:
                    try:
                        target.proc.kill()
                    except Exception:
                        pass
        target.status = "released"
        self.emit_event(
            "target_released",
            {
                "target_id": target.target_id,
                "reason": reason,
                "target": target.to_record(
                    repo_root=self.config.repo_root, stage=self.config.stage, lane=self.config.lane
                ),
            },
        )

    def _cmd_terminate(self) -> Dict[str, object]:
        self.shutdown()
        return {"status": "terminated"}

    def _cmd_subscribe(self) -> Dict[str, object]:
        return {
            "events_path": path_utils.to_repo_relative(self.config.events_path, self.config.repo_root),
        }

    def _lease_loop(self) -> None:
        while not self._stop.is_set():
            now = time.monotonic()
            expired: List[TargetState] = []
            with self._lock:
                for target in self.targets.values():
                    if target.lease_deadline_s and now >= target.lease_deadline_s:
                        expired.append(target)
            for target in expired:
                try:
                    self._release_target(target, reason="lease_expired")
                except KeepaliveError:
                    continue
            self._stop.wait(0.5)

    def _close_hooks_for_target(self, target_id: str) -> None:
        to_close: List[HookState] = []
        with self._lock:
            for hook in self.hooks.values():
                if hook.target_id != target_id:
                    continue
                to_close.append(hook)
        for hook in to_close:
            if hook.proc is not None:
                try:
                    self._helper_request(hook, {"type": "close"}, timeout_s=1.0)
                except KeepaliveError:
                    pass
                try:
                    if hook.proc.poll() is None:
                        hook.proc.terminate()
                        hook.proc.wait(timeout=2.0)
                except Exception:
                    try:
                        hook.proc.kill()
                    except Exception:
                        pass
                hook.proc = None
            capture = hook.capture
            if capture is not None and hasattr(capture, "close"):
                try:
                    capture.close()
                except Exception:
                    pass
            hook.status = "closed"
            self.emit_event(
                "hook_closed",
                {
                    "hook_id": hook.hook_id,
                    "hook": hook.to_record(
                        repo_root=self.config.repo_root, stage=self.config.stage, lane=self.config.lane
                    ),
                },
            )


class KeepaliveClient:
    def __init__(self, control_path: Path, *, stage: str = "operation", lane: str = "oracle") -> None:
        self.control_path = control_path
        self.stage = stage
        self.lane = lane

    def _request(self, request_type: str, params: Optional[Dict[str, object]] = None) -> Dict[str, object]:
        request_id = str(uuid.uuid4())
        payload = {
            "id": request_id,
            "type": request_type,
            "params": params or {},
            "meta": {"stage": self.stage, "lane": self.lane},
        }
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(str(self.control_path))
            sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            buff = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buff += chunk
                if b"\n" in buff:
                    break
        line = buff.decode("utf-8", errors="replace").splitlines()[0] if buff else ""
        if not line:
            raise KeepaliveError("no_response", "keepalive daemon did not respond")
        response = json.loads(line)
        if not isinstance(response, dict) or not response.get("ok"):
            error = response.get("error") if isinstance(response, dict) else None
            if isinstance(error, dict):
                raise KeepaliveError(
                    str(error.get("code") or "error"),
                    str(error.get("message") or "request failed"),
                    kind=str(error.get("kind") or "request_error"),
                    limits=error.get("limits") if isinstance(error.get("limits"), str) else None,
                    details=error.get("details") if isinstance(error.get("details"), dict) else None,
                )
            raise KeepaliveError("request_failed", "keepalive request failed")
        result = response.get("result")
        if not isinstance(result, dict):
            raise KeepaliveError("bad_response", "missing result in response")
        return result

    def hello(self) -> Dict[str, object]:
        return self._request("hello")

    def start_target(self, **params: object) -> Dict[str, object]:
        return self._request("start_target", params)

    def attach_target(self, **params: object) -> Dict[str, object]:
        return self._request("attach_target", params)

    def hook_target(self, **params: object) -> Dict[str, object]:
        return self._request("hook_target", params)

    def hook_finalize(self, **params: object) -> Dict[str, object]:
        return self._request("hook_finalize", params)

    def status(self, **params: object) -> Dict[str, object]:
        return self._request("status", params)

    def renew_lease(self, **params: object) -> Dict[str, object]:
        return self._request("renew_lease", params)

    def release(self, **params: object) -> Dict[str, object]:
        return self._request("release", params)

    def terminate(self) -> Dict[str, object]:
        return self._request("terminate")

    def subscribe(self) -> Dict[str, object]:
        return self._request("subscribe")


class KeepaliveService:
    def __init__(
        self,
        *,
        config: Optional[KeepaliveConfig] = None,
        stage: str = "operation",
        lane: str = "oracle",
    ) -> None:
        self.config = config or KeepaliveConfig.default(stage=stage, lane=lane, repo_root=REPO_ROOT)
        self.daemon = KeepaliveDaemon(self.config)
        self.client = KeepaliveClient(self.config.control_path, stage=stage, lane=lane)
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        try:
            self.daemon.start()
        except Exception as exc:
            raise KeepaliveError(
                "keepalive_start_failed",
                f"keepalive daemon failed to start: {type(exc).__name__}: {exc}",
            ) from exc
        self._thread = threading.Thread(target=self.daemon.serve_forever, name="keepalive-daemon", daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 2.0
        while time.monotonic() <= deadline:
            if self.config.control_path.exists():
                return
            time.sleep(0.05)
        raise RuntimeError("keepalive daemon did not start")

    def close(self) -> None:
        self.daemon.shutdown()
        if self._thread:
            self._thread.join(timeout=1.0)

    def __enter__(self) -> "KeepaliveService":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def _frida_available() -> bool:
    try:
        import frida  # type: ignore
    except Exception:
        return False
    return True


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="command")
    serve = sub.add_parser("serve", help="Start keepalive daemon")
    serve.add_argument("--control-socket", help="Control socket path")
    serve.add_argument("--events", help="Events JSONL path")
    serve.add_argument("--stage", default="operation", choices=["compile", "apply", "bootstrap", "operation"])
    serve.add_argument("--lane", default="oracle", choices=["scenario", "baseline", "oracle"])
    hook_frida = sub.add_parser("hook-frida", help="Attach Frida to a PID via keepalive")
    hook_frida.add_argument("--pid", type=int, help="PID to attach")
    hook_frida.add_argument(
        "--spawn-hold-open",
        action="store_true",
        help="Spawn hold_open and attach to it instead of providing --pid",
    )
    hook_frida.add_argument(
        "--wait-spec",
        default="fifo:auto",
        help="Wait spec for hold_open spawn (default: fifo:auto)",
    )
    hook_frida.add_argument("--ready-timeout-s", type=float, default=10.0, help="Spawn ready timeout")
    hook_frida.add_argument("--script", required=True, help="Frida JS hook script")
    hook_frida.add_argument("--out-dir", default="book/api/witness/out/keepalive/frida", help="Output dir for hook run")
    hook_frida.add_argument("--frida-config", help="JSON object for script configure()")
    hook_frida.add_argument("--frida-config-path", help="Path to JSON file for script configure()")
    hook_frida.add_argument("--attach-meta", help="JSON object for attach metadata")
    hook_frida.add_argument("--attach-meta-path", help="Path to JSON file for attach metadata")
    hook_frida.add_argument("--run-id", help="Override Frida run_id")
    hook_frida.add_argument("--no-finalize", action="store_true", help="Skip hook_finalize")
    hook_frida.add_argument("--gate-release", action="store_true", help="Gate release on hook readiness")
    hook_frida.add_argument("--helper", action="store_true", help="Use the signed Frida attach helper")
    hook_frida.add_argument("--helper-path", help="Override helper path")
    hook_frida.add_argument("--stage", default="operation", choices=["compile", "apply", "bootstrap", "operation"])
    hook_frida.add_argument("--lane", default="oracle", choices=["scenario", "baseline", "oracle"])
    return ap


def _load_json_arg(value: Optional[str], *, label: str) -> Optional[Dict[str, object]]:
    if value is None:
        return None
    try:
        obj = json.loads(value)
    except Exception as exc:
        raise KeepaliveError("bad_request", f"{label} invalid json: {exc}") from exc
    if not isinstance(obj, dict):
        raise KeepaliveError("bad_request", f"{label} must be a JSON object")
    return obj


def _load_json_path(path: Optional[str], *, label: str, repo_root: Path) -> Optional[Dict[str, object]]:
    if path is None:
        return None
    abs_path = path_utils.ensure_absolute(path, repo_root)
    try:
        obj = json.loads(abs_path.read_text())
    except Exception as exc:
        raise KeepaliveError("bad_request", f"{label} could not read: {exc}") from exc
    if not isinstance(obj, dict):
        raise KeepaliveError("bad_request", f"{label} must be a JSON object")
    return obj


def _run_hook_frida(args: argparse.Namespace) -> int:
    repo_root = path_utils.find_repo_root()
    world_id = baseline_world_id(repo_root)
    payload: Dict[str, object] = {
        "schema_version": 1,
        "world_id": world_id,
        "stage": args.stage,
        "lane": args.lane,
    }
    if args.spawn_hold_open and args.pid:
        raise SystemExit("use only one of --pid or --spawn-hold-open")
    if not args.spawn_hold_open and not args.pid:
        raise SystemExit("missing --pid (or use --spawn-hold-open)")

    attach_meta = _load_json_arg(args.attach_meta, label="attach_meta") or {}
    attach_meta_path = _load_json_path(args.attach_meta_path, label="attach_meta_path", repo_root=repo_root)
    if attach_meta_path:
        attach_meta.update(attach_meta_path)

    service = KeepaliveService(stage=args.stage, lane=args.lane)
    try:
        service.start()
    except KeepaliveError as exc:
        payload["error"] = exc.to_dict()
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 1

    client = service.client
    target = None
    target_id: Optional[str] = None
    hook = None
    finalize = {"status": "skipped", "reason": "not_run"}
    error = None
    try:
        if args.spawn_hold_open:
            target_res = client.start_target(mode="spawn", wait_spec=args.wait_spec, ready_timeout_s=args.ready_timeout_s)
        else:
            target_res = client.attach_target(pid=args.pid)
        target = target_res.get("target") if isinstance(target_res, dict) else None
        if not isinstance(target, dict):
            raise KeepaliveError("missing_target", "keepalive did not return target")
        target_id = target.get("target_id") if isinstance(target.get("target_id"), str) else None
        pid = target.get("pid")
        if isinstance(pid, int):
            attach_meta.setdefault("pid", pid)
        if target_id:
            attach_meta.setdefault("target_id", target_id)
        attach_meta.setdefault(
            "script_path",
            path_utils.to_repo_relative(args.script, repo_root),
        )
        helper_path = None
        if args.helper or args.helper_path:
            helper_path = args.helper_path or str(WITNESS_FRIDA_ATTACH_HELPER)
            helper_path = path_utils.to_repo_relative(helper_path, repo_root)

        hook_res = client.hook_target(
            kind="frida",
            target_id=target_id,
            run_id=args.run_id,
            script_path=path_utils.to_repo_relative(args.script, repo_root),
            out_dir=path_utils.to_repo_relative(args.out_dir, repo_root),
            config_json=args.frida_config,
            config_path=(
                path_utils.to_repo_relative(args.frida_config_path, repo_root)
                if args.frida_config_path
                else None
            ),
            helper_path=helper_path,
            gate_release=bool(args.gate_release),
        )
        hook = hook_res.get("hook") if isinstance(hook_res, dict) else None
        if not isinstance(hook, dict):
            raise KeepaliveError("missing_hook", "keepalive did not return hook")
        hook_id = hook.get("hook_id")
        if args.no_finalize:
            finalize = {"status": "skipped", "reason": "disabled"}
        elif hook.get("status") != "ready":
            finalize = {"status": "skipped", "reason": "hook_not_ready", "error": hook.get("error")}
        elif isinstance(hook_id, str):
            finalize_res = client.hook_finalize(hook_id=hook_id, attach_meta=attach_meta)
            finalize = {"status": "ok", "result": finalize_res}
        else:
            finalize = {"status": "skipped", "reason": "missing_hook_id"}
    except KeepaliveError as exc:
        error = exc.to_dict()
    finally:
        if target_id:
            try:
                client.release(target_id=target_id)
            except KeepaliveError:
                pass
        service.close()

    payload["keepalive"] = {
        "run_id": service.config.run_id,
        "events_path": path_utils.to_repo_relative(service.config.events_path, repo_root),
        "control_path": path_utils.to_repo_relative(service.config.control_path, repo_root),
    }
    if target is not None:
        payload["target"] = target
    if hook is not None:
        payload["hook"] = hook
    payload["hook_finalize"] = finalize
    if error:
        payload["error"] = error
    print(json.dumps(payload, indent=2, sort_keys=True))
    if error or (hook is not None and hook.get("status") != "ready"):
        return 1
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.command == "serve":
        repo_root = path_utils.find_repo_root()
        base = KeepaliveConfig.default(stage=args.stage, lane=args.lane, repo_root=repo_root)
        control = (
            path_utils.ensure_absolute(args.control_socket, repo_root) if args.control_socket else base.control_path
        )
        events = path_utils.ensure_absolute(args.events, repo_root) if args.events else base.events_path
        config = KeepaliveConfig(
            control_path=control,
            events_path=events,
            stage=args.stage,
            lane=args.lane,
            world_id=baseline_world_id(repo_root),
            repo_root=repo_root,
            run_id=base.run_id,
        )
        daemon = KeepaliveDaemon(config)
        daemon.start()
        try:
            daemon.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            daemon.shutdown()
        return 0
    if args.command == "hook-frida":
        return _run_hook_frida(args)
    raise SystemExit("use: keepalive serve | hook-frida")


if __name__ == "__main__":
    raise SystemExit(main())
