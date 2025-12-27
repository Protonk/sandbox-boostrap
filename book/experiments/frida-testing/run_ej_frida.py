#!/usr/bin/env python3
import argparse
import json
import os
import platform
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import frida

from book.api import path_utils
from book.api.entitlementjail import cli as ej_cli
from book.api.entitlementjail.logging import extract_details
from book.api.entitlementjail.session import XpcSession
from book.api.profile_tools.identity import baseline_world_id


def sha256_bytes(blob: bytes) -> str:
    import hashlib

    h = hashlib.sha256()
    h.update(blob)
    return h.hexdigest()


def now_ns() -> int:
    return time.time_ns()


def write_json(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def find_pids_by_name(process_name: str) -> Tuple[List[int], Optional[str]]:
    try:
        out = subprocess.check_output(["pgrep", "-x", process_name], text=True).strip()
    except subprocess.CalledProcessError:
        return [], None
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"
    if not out:
        return [], None
    pids: List[int] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            pids.append(int(line))
        except Exception:
            continue
    return pids, None


def wait_for_pid(process_name: str, timeout_s: float) -> Tuple[Optional[int], List[int], Optional[str]]:
    deadline = time.monotonic() + max(timeout_s, 0.0)
    candidates: List[int] = []
    error: Optional[str] = None
    while time.monotonic() <= deadline:
        candidates, error = find_pids_by_name(process_name)
        if candidates:
            break
        time.sleep(0.05)
    if not candidates:
        return None, candidates, error
    return max(candidates), candidates, error


class FridaCapture:
    def __init__(
        self,
        *,
        pid: int,
        script_path: Path,
        events_path: Path,
        meta_path: Path,
        config: Optional[Dict[str, object]],
        repo_root: Path,
    ) -> None:
        self.pid = pid
        self.script_path = script_path
        self.events_path = events_path
        self.meta_path = meta_path
        self.config = config
        self.repo_root = repo_root
        self.events_fp = self.events_path.open("w", encoding="utf-8")
        self.session = None
        self.script = None
        self.js_src = self.script_path.read_bytes()

    def _write_event(self, msg: Dict[str, object]) -> None:
        rec = {
            "t_ns": now_ns(),
            "pid": self.pid,
            "msg": msg,
        }
        self.events_fp.write(json.dumps(rec, separators=(",", ":")) + "\n")
        self.events_fp.flush()

    def _emit_runner(self, kind: str, **fields: object) -> None:
        payload = {"kind": kind}
        payload.update(fields)
        self._write_event({"type": "runner", "payload": payload})

    def attach(self) -> Optional[str]:
        self._emit_runner("runner-start")
        try:
            self._emit_runner("stage", stage="device")
            device = frida.get_local_device()
            self._emit_runner("stage", stage="attach")
            self.session = device.attach(self.pid)

            def on_detached(reason, crash=None):
                payload = {"reason": str(reason)}
                if crash:
                    payload["crash"] = crash
                self._emit_runner("session-detached", **payload)

            self.session.on("detached", on_detached)

            def on_message(msg, data):
                self._write_event(msg)

            self._emit_runner("stage", stage="script-load")
            self.script = self.session.create_script(self.js_src.decode("utf-8"))
            self.script.on("message", on_message)
            self.script.load()

            if self.config:
                self._emit_runner("stage", stage="script-config")
                try:
                    self.script.exports_sync.configure(self.config)
                except Exception as exc:
                    self._emit_runner("script-config-error", error=str(exc))
        except Exception as exc:
            self._emit_runner("runner-exception", error=str(exc))
            return f"{type(exc).__name__}: {exc}"
        return None

    def finalize_meta(self, *, world_id: str, attach_meta: Dict[str, object]) -> None:
        meta = {
            "run_id": attach_meta.get("run_id"),
            "world_id": world_id,
            "t0_ns": attach_meta.get("t0_ns"),
            "out_dir": path_utils.to_repo_relative(self.events_path.parent.parent, self.repo_root),
            "host": {
                "platform": platform.platform(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "frida": {
                "python_pkg_version": getattr(frida, "__version__", None),
            },
            "script": {
                "path": path_utils.to_repo_relative(self.script_path, self.repo_root),
                "sha256": sha256_bytes(self.js_src),
            },
            "attach": attach_meta,
            "config": self.config,
        }
        write_json(self.meta_path, meta)

    def close(self) -> None:
        try:
            if self.session is not None:
                self.session.detach()
        finally:
            self.events_fp.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile-id", required=True, help="EntitlementJail profile id")
    ap.add_argument("--service-id", help="Override service bundle id (skip --profile)")
    ap.add_argument("--service-name", help="Override process name for attach")
    ap.add_argument("--ack-risk", help="Tier-2 ack token for EntitlementJail")
    ap.add_argument("--probe-id", required=True, help="Probe id to run via run-xpc")
    ap.add_argument(
        "--probe-args",
        nargs=argparse.REMAINDER,
        default=[],
        help="Probe args (pass after --probe-args)",
    )
    ap.add_argument("--script", required=True, help="Frida JS hook script")
    ap.add_argument(
        "--out-dir",
        default="book/experiments/frida-testing/out",
        help="Output root for run artifacts",
    )
    ap.add_argument("--plan-id", default="frida-testing:ej-frida", help="Plan id for correlation")
    ap.add_argument("--row-id", default=None, help="Row id override (default: plan_id.run_id)")
    ap.add_argument("--attach-seconds", type=int, default=30, help="Seconds to wait before triggering")
    ap.add_argument("--hold-open-seconds", type=int, default=20, help="Seconds to keep the service open")
    ap.add_argument("--trigger-delay-s", type=float, default=0.0, help="Delay before triggering wait")
    ap.add_argument("--attach-timeout-s", type=float, default=5.0, help="Attach PID lookup timeout")
    ap.add_argument(
        "--attach-stage",
        choices=["wait", "post-trigger"],
        default="wait",
        help="Attach before trigger (wait) or after trigger (post-trigger)",
    )
    ap.add_argument(
        "--post-trigger-attach-delay-s",
        type=float,
        default=0.0,
        help="Delay before post-trigger attach",
    )
    ap.add_argument("--selftest-path", help="Override selftest path for fs_open_selftest.js")
    ap.add_argument("--selftest-name", default="ej_noaccess", help="File name under tmp_dir")
    ap.add_argument("--skip-capabilities", action="store_true", help="Skip capabilities_snapshot")
    ap.add_argument(
        "--no-prepare-selftest",
        action="store_true",
        help="Do not create/chmod the selftest path",
    )
    args = ap.parse_args()

    repo_root = path_utils.find_repo_root()
    world_id = baseline_world_id(repo_root)

    if args.profile_id == "fully_injectable" and not args.ack_risk:
        raise SystemExit("fully_injectable requires --ack-risk fully_injectable")

    run_id = str(uuid.uuid4())
    row_id = args.row_id or f"{args.plan_id}.{run_id}"
    out_root = path_utils.ensure_absolute(args.out_dir, repo_root) / run_id
    ej_dir = out_root / "ej"
    frida_dir = out_root / "frida"
    logs_dir = ej_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    frida_dir.mkdir(parents=True, exist_ok=True)

    use_profile = args.service_id is None
    target_profile_id = args.profile_id if use_profile else None
    target_service_id = args.service_id if not use_profile else None

    cap_record = None
    tmp_dir = None
    process_name = args.service_name
    if not args.skip_capabilities:
        cap_log_path = logs_dir / "capabilities_snapshot.log"
        cap_record = ej_cli.run_xpc(
            profile_id=target_profile_id,
            service_id=target_service_id,
            probe_id="capabilities_snapshot",
            probe_args=[],
            log_path=cap_log_path,
            plan_id=args.plan_id,
            row_id=f"{row_id}.capabilities_snapshot",
            ack_risk=args.ack_risk,
        )
        write_json(ej_dir / "capabilities_snapshot.json", cap_record)
        details = extract_details(cap_record.get("stdout_json"))
        if isinstance(details, dict):
            tmp_dir = details.get("tmp_dir")
            if process_name is None:
                process_name = details.get("process_name")

    selftest_path = args.selftest_path
    selftest_source = "cli" if selftest_path else None
    if not selftest_path and tmp_dir:
        selftest_path = os.path.join(str(tmp_dir), args.selftest_name)
        selftest_source = "capabilities_snapshot"

    selftest_prepared = None
    selftest_prepare_error = None
    if selftest_path and not args.no_prepare_selftest:
        try:
            Path(selftest_path).parent.mkdir(parents=True, exist_ok=True)
            Path(selftest_path).write_text("")
            os.chmod(selftest_path, 0o000)
            selftest_prepared = True
        except Exception as exc:
            selftest_prepared = False
            selftest_prepare_error = f"{type(exc).__name__}: {exc}"

    script_path = path_utils.ensure_absolute(args.script, repo_root)
    frida_events_path = frida_dir / "events.jsonl"
    frida_meta_path = frida_dir / "meta.json"

    attach_meta: Dict[str, object] = {
        "run_id": run_id,
        "t0_ns": now_ns(),
        "pid_source": "pgrep",
        "pid_candidates": [],
        "attach_stage": args.attach_stage,
    }

    frida_capture: Optional[FridaCapture] = None
    frida_attach_error: Optional[str] = None

    def attach_now(stage: str, info: Optional[Dict[str, object]] = None) -> None:
        nonlocal frida_capture, frida_attach_error
        attach_meta["attach_stage"] = stage
        if info is not None:
            if stage == "post-trigger":
                attach_meta["trigger_info"] = info
            else:
                attach_meta["wait_info"] = info
        if stage == "post-trigger" and args.post_trigger_attach_delay_s > 0:
            time.sleep(args.post_trigger_attach_delay_s)
        if not process_name:
            attach_meta["pid_error"] = "missing_process_name"
            return
        pid, candidates, pid_error = wait_for_pid(process_name, args.attach_timeout_s)
        attach_meta["pid_candidates"] = candidates
        attach_meta["pid_error"] = pid_error
        if pid is None:
            attach_meta["pid_error"] = attach_meta.get("pid_error") or "pid_not_found"
            return
        attach_meta["pid"] = pid
        config = {"selftest_path": selftest_path} if selftest_path else None
        frida_capture = FridaCapture(
            pid=pid,
            script_path=script_path,
            events_path=frida_events_path,
            meta_path=frida_meta_path,
            config=config,
            repo_root=repo_root,
        )
        frida_attach_error = frida_capture.attach()

    def on_wait_ready(wait_info: Dict[str, object]) -> None:
        if args.attach_stage == "wait":
            attach_now("wait", wait_info)
        else:
            attach_meta["wait_info"] = wait_info

    def on_trigger(trigger_info: Dict[str, object]) -> None:
        if args.attach_stage == "post-trigger":
            attach_now("post-trigger", trigger_info)

    log_path = logs_dir / "run_xpc.log"
    wait_timeout_ms = max(max(args.attach_seconds, 0) * 1000, 15000)
    session = XpcSession(
        profile_id=target_profile_id,
        service_id=target_service_id,
        plan_id=args.plan_id,
        correlation_id=row_id,
        ack_risk=args.ack_risk,
        wait_spec="fifo:auto",
        wait_timeout_ms=wait_timeout_ms,
    )
    trigger_events: List[Dict[str, object]] = []
    probe_started_at_unix_s = None
    probe_finished_at_unix_s = None
    probe_response = None
    session_error: Optional[str] = None
    try:
        try:
            session.start(ready_timeout_s=max(args.attach_seconds, 15))
            wait_info = {
                "wait_path": session.wait_path(),
                "wait_mode": session.wait_mode(),
                "wait_timeout_ms": wait_timeout_ms,
                "session_ready": session.session_ready.get("data") if isinstance(session.session_ready, dict) else None,
                "wait_ready": session.wait_ready.get("data") if isinstance(session.wait_ready, dict) else None,
            }
            on_wait_ready(wait_info)
            if args.trigger_delay_s > 0:
                time.sleep(args.trigger_delay_s)
            trigger_at = time.time()
            trigger_error = session.trigger_wait(nonblocking=False, timeout_s=2.0)
            trigger_events.append({"kind": "primary", "at_unix_s": trigger_at, "error": trigger_error})
            on_trigger(
                {
                    "wait_path": wait_info["wait_path"],
                    "wait_mode": wait_info["wait_mode"],
                    "wait_timeout_ms": wait_timeout_ms,
                    "trigger": trigger_events[-1],
                    "trigger_events": list(trigger_events),
                }
            )
            trigger_received = session.wait_for_trigger_received(timeout_s=2.0)
            if trigger_received is None:
                session_error = session_error or "trigger_received_timeout"
            probe_started_at_unix_s = time.time()
            probe_response = session.run_probe(probe_id=args.probe_id, argv=args.probe_args)
            probe_finished_at_unix_s = time.time()
            if args.hold_open_seconds > 0:
                time.sleep(args.hold_open_seconds)
        except Exception as exc:
            session_error = f"{type(exc).__name__}: {exc}"
    finally:
        session.close()

    stdout_text = "".join(session.stdout_lines).rstrip()
    stderr_text = "".join(session.stderr_lines).rstrip()
    log_write_error = None
    if stdout_text:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(stdout_text + "\n")
        except Exception as exc:
            log_write_error = f"{type(exc).__name__}: {exc}"

    record = {
        "command": session.command(),
        "exit_code": session.exit_code,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "error": session_error,
        "plan_id": args.plan_id,
        "row_id": row_id,
        "correlation_id": row_id,
        "wait_spec": "fifo:auto",
        "wait_timeout_ms": wait_timeout_ms,
        "trigger_delay_s": args.trigger_delay_s,
        "trigger_events": trigger_events,
        "probe_id": args.probe_id,
        "probe_args": list(args.probe_args),
        "probe_started_at_unix_s": probe_started_at_unix_s,
        "probe_finished_at_unix_s": probe_finished_at_unix_s,
        "hold_open_s": args.hold_open_seconds,
        "log_path": path_utils.to_repo_relative(log_path, repo_root),
        "log_write_error": log_write_error,
        "session_ready": session.session_ready,
        "wait_ready": session.wait_ready,
        "stdout_json": probe_response,
        "stdout_jsonl_kinds": {
            k: sum(1 for o in session.stdout_jsonl if o.get("kind") == k)
            for k in {o.get("kind") for o in session.stdout_jsonl if isinstance(o, dict)}
        },
    }
    write_json(ej_dir / "run_xpc.json", record)

    service_pid = None
    details = extract_details(record.get("stdout_json"))
    if isinstance(details, dict):
        service_pid = details.get("service_pid")
        if process_name is None:
            process_name = details.get("process_name")

    if frida_capture is not None:
        attach_meta["service_pid"] = service_pid
        if service_pid is not None and "pid" in attach_meta:
            attach_meta["pid_matches_service_pid"] = str(service_pid) == str(attach_meta["pid"])
        frida_capture.finalize_meta(world_id=world_id, attach_meta=attach_meta)
        frida_capture.close()

    manifest = {
        "schema_version": 1,
        "world_id": world_id,
        "run_id": run_id,
        "plan_id": args.plan_id,
        "row_id": row_id,
        "out_dir": path_utils.to_repo_relative(out_root, repo_root),
        "probe": {
            "profile_id": args.profile_id,
            "service_id": target_service_id,
            "use_profile": use_profile,
            "probe_id": args.probe_id,
            "probe_args": list(args.probe_args),
            "ack_risk": args.ack_risk,
        },
        "entitlementjail": {
            "run_xpc_path": path_utils.to_repo_relative(ej_dir / "run_xpc.json", repo_root),
            "capabilities_snapshot_path": (
                path_utils.to_repo_relative(ej_dir / "capabilities_snapshot.json", repo_root)
                if cap_record
                else None
            ),
            "log_path": path_utils.to_repo_relative(log_path, repo_root),
        },
        "frida": {
            "events_path": (
                path_utils.to_repo_relative(frida_events_path, repo_root)
                if frida_events_path.exists()
                else None
            ),
            "meta_path": (
                path_utils.to_repo_relative(frida_meta_path, repo_root)
                if frida_meta_path.exists()
                else None
            ),
            "attach_error": frida_attach_error,
            "attach_meta": attach_meta,
        },
        "selftest": {
            "path": selftest_path,
            "source": selftest_source,
            "prepared": selftest_prepared,
            "prepare_error": selftest_prepare_error,
        },
    }
    write_json(out_root / "manifest.json", manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
