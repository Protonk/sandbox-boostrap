"""Attach-first Frida harness for PolicyWitness XPC sessions."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from book.api import path_utils
from book.api.witness import client as witness_client
from book.api.witness import keepalive, lifecycle, outputs
from book.api.witness.paths import WITNESS_FRIDA_ATTACH_HELPER
from book.api.witness.session import XpcSession
from book.api.frida.capture import FridaCapture, now_ns
from book.api.profile.identity import baseline_world_id


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


def add_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--profile-id", required=True, help="PolicyWitness profile id")
    ap.add_argument("--service-name", help="Override process name for attach")
    ap.add_argument("--probe-id", required=True, help="Probe id to run via xpc session")
    ap.add_argument(
        "--probe-args",
        nargs=argparse.REMAINDER,
        default=[],
        help="Probe args (pass after --probe-args)",
    )
    ap.add_argument("--script", required=True, help="Frida JS hook script")
    ap.add_argument("--frida-config", help="JSON object for script configure()")
    ap.add_argument("--frida-config-path", help="Path to JSON file for script configure()")
    ap.add_argument(
        "--out-dir",
        default="book/api/witness/out",
        help="Output root for run artifacts",
    )
    ap.add_argument(
        "--plan-id",
        default="frida-testing:witness-frida",
        help="Plan id for correlation",
    )
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
    ap.add_argument("--selftest-name", default="pw_noaccess", help="File name under tmp_dir")
    ap.add_argument("--skip-capabilities", action="store_true", help="Skip capabilities_snapshot")
    ap.add_argument(
        "--no-prepare-selftest",
        action="store_true",
        help="Do not create/chmod the selftest path",
    )
    ap.add_argument(
        "--keepalive",
        action="store_true",
        help="Use keepalive daemon for Frida attach (PolicyWitness session remains direct)",
    )
    ap.add_argument(
        "--frida-helper",
        action="store_true",
        help="Use the signed Frida attach helper for keepalive attach",
    )
    ap.add_argument("--frida-helper-path", help="Override helper path")


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    add_arguments(ap)
    return ap


def run_from_args(args: argparse.Namespace) -> int:
    if (args.frida_helper or args.frida_helper_path) and not args.keepalive:
        raise SystemExit("--frida-helper requires --keepalive")
    repo_root = path_utils.find_repo_root()
    world_id = baseline_world_id(repo_root)

    run_id = str(uuid.uuid4())
    row_id = args.row_id or f"{args.plan_id}.{run_id}"
    out_root = path_utils.ensure_absolute(args.out_dir, repo_root) / run_id
    witness_dir = out_root / "witness"
    frida_dir = out_root / "frida"
    logs_dir = witness_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    frida_dir.mkdir(parents=True, exist_ok=True)

    target_profile_id = args.profile_id

    cap_record = None
    tmp_dir = None
    process_name = args.service_name
    if not args.skip_capabilities:
        cap_log_path = logs_dir / "capabilities_snapshot.log"
        cap_result = witness_client.run_probe(
            profile_id=target_profile_id,
            probe_id="capabilities_snapshot",
            probe_args=[],
            plan_id=args.plan_id,
            row_id=f"{row_id}.capabilities_snapshot",
            output=outputs.OutputSpec(log_path=cap_log_path),
        )
        cap_record = cap_result.to_json()
        write_json(witness_dir / "capabilities_snapshot.json", cap_record)
        details = lifecycle.extract_details(cap_result.stdout_json)
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
    keepalive_service: Optional[keepalive.KeepaliveService] = None
    keepalive_target_id: Optional[str] = None
    keepalive_hook_id: Optional[str] = None
    keepalive_hook_record: Optional[Dict[str, object]] = None
    keepalive_error: Optional[str] = None
    keepalive_events_path: Optional[str] = None

    def _ensure_keepalive() -> Optional[keepalive.KeepaliveService]:
        nonlocal keepalive_service, keepalive_error, keepalive_events_path
        if keepalive_service is not None:
            return keepalive_service
        try:
            keepalive_service = keepalive.KeepaliveService(stage="operation", lane="oracle")
            keepalive_service.start()
            keepalive_events_path = path_utils.to_repo_relative(
                keepalive_service.config.events_path, repo_root
            )
            return keepalive_service
        except keepalive.KeepaliveError as exc:
            keepalive_error = f"{exc.code}: {exc.message}"
        except Exception as exc:
            keepalive_error = f"{type(exc).__name__}: {exc}"
        return None

    def _resolve_pid(session: XpcSession) -> Optional[int]:
        session_pid = session.pid()
        if session_pid is not None:
            attach_meta["pid_source"] = "session_ready"
            attach_meta["pid_candidates"] = [session_pid]
            attach_meta["pid_error"] = None
            attach_meta["pid"] = session_pid
            return session_pid
        if not process_name:
            attach_meta["pid_error"] = "missing_process_name"
            return None
        pid, candidates, pid_error = wait_for_pid(process_name, args.attach_timeout_s)
        attach_meta["pid_source"] = "pgrep"
        attach_meta["pid_candidates"] = candidates
        attach_meta["pid_error"] = pid_error
        if pid is None:
            attach_meta["pid_error"] = attach_meta.get("pid_error") or "pid_not_found"
            return None
        attach_meta["pid"] = pid
        return pid

    def _attach_with_frida(pid: int) -> None:
        nonlocal frida_capture, frida_attach_error
        config_overlay: Dict[str, object] = {}
        config_overlay_source: Dict[str, object] = {"kind": "overlay"}
        if selftest_path:
            config_overlay["selftest_path"] = selftest_path
            if selftest_source:
                config_overlay_source["source"] = selftest_source
        frida_capture = FridaCapture(
            run_id=run_id,
            pid=pid,
            script_path=script_path,
            events_path=frida_events_path,
            meta_path=frida_meta_path,
            config_json=args.frida_config,
            config_path=args.frida_config_path,
            config_overlay=config_overlay,
            config_overlay_source=config_overlay_source,
            repo_root=repo_root,
        )
        frida_attach_error = frida_capture.attach()

    def _attach_with_keepalive(pid: int) -> None:
        nonlocal frida_attach_error, keepalive_target_id, keepalive_hook_id, keepalive_hook_record, keepalive_error
        service = _ensure_keepalive()
        if service is None:
            frida_attach_error = keepalive_error or "keepalive_start_failed"
            return
        try:
            attach_res = service.client.attach_target(pid=pid)
            target = attach_res.get("target") if isinstance(attach_res, dict) else None
            if not isinstance(target, dict):
                frida_attach_error = "keepalive_attach_missing_target"
                return
            keepalive_target_id = target.get("target_id")
        except keepalive.KeepaliveError as exc:
            frida_attach_error = f"KeepaliveError:{exc.code}:{exc.message}"
            return

        config_overlay: Dict[str, object] = {}
        config_overlay_source: Dict[str, object] = {"kind": "overlay"}
        if selftest_path:
            config_overlay["selftest_path"] = selftest_path
            if selftest_source:
                config_overlay_source["source"] = selftest_source
        config_path = None
        if args.frida_config_path:
            config_path = path_utils.to_repo_relative(args.frida_config_path, repo_root)
        out_dir_arg = path_utils.to_repo_relative(frida_dir, repo_root)
        helper_path = None
        if args.frida_helper or args.frida_helper_path:
            helper_path = args.frida_helper_path or str(WITNESS_FRIDA_ATTACH_HELPER)
            helper_path = path_utils.to_repo_relative(helper_path, repo_root)
        try:
            hook_res = service.client.hook_target(
                kind="frida",
                target_id=keepalive_target_id,
                run_id=run_id,
                script_path=path_utils.to_repo_relative(script_path, repo_root),
                config_json=args.frida_config,
                config_path=config_path,
                config_overlay=config_overlay,
                out_dir=out_dir_arg,
                helper_path=helper_path,
                gate_release=False,
            )
            hook = hook_res.get("hook") if isinstance(hook_res, dict) else None
            if not isinstance(hook, dict):
                frida_attach_error = "keepalive_hook_missing_record"
                return
            keepalive_hook_record = hook
            keepalive_hook_id = hook.get("hook_id")
            if hook.get("status") != "ready":
                frida_attach_error = hook.get("error") or "keepalive_hook_error"
        except keepalive.KeepaliveError as exc:
            frida_attach_error = f"KeepaliveError:{exc.code}:{exc.message}"

    def attach_now(session: XpcSession, stage: str, info: Optional[Dict[str, object]] = None) -> None:
        nonlocal frida_attach_error
        attach_meta["attach_stage"] = stage
        if info is not None:
            if stage == "post-trigger":
                attach_meta["trigger_info"] = info
            else:
                attach_meta["wait_info"] = info
        if stage == "post-trigger" and args.post_trigger_attach_delay_s > 0:
            time.sleep(args.post_trigger_attach_delay_s)
        pid = _resolve_pid(session)
        if pid is None:
            frida_attach_error = attach_meta.get("pid_error") or "pid_not_found"
            return
        if args.keepalive:
            _attach_with_keepalive(pid)
        else:
            _attach_with_frida(pid)

    def on_wait_ready(session: XpcSession, wait_info: Dict[str, object]) -> None:
        if args.attach_stage == "wait":
            attach_now(session, "wait", wait_info)
        else:
            attach_meta["wait_info"] = wait_info

    def on_trigger(session: XpcSession, trigger_info: Dict[str, object]) -> None:
        if args.attach_stage == "post-trigger":
            attach_now(session, "post-trigger", trigger_info)

    log_path = logs_dir / "run_probe.log"
    wait_timeout_ms = max(max(args.attach_seconds, 0) * 1000, 15000)
    session = XpcSession(
        profile_id=target_profile_id,
        plan_id=args.plan_id,
        correlation_id=row_id,
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
            on_wait_ready(session, wait_info)
            if args.trigger_delay_s > 0:
                time.sleep(args.trigger_delay_s)
            trigger_at = time.time()
            trigger_error = session.trigger_wait(nonblocking=False, timeout_s=2.0)
            trigger_events.append({"kind": "primary", "at_unix_s": trigger_at, "error": trigger_error})
            on_trigger(
                session,
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
    write_json(witness_dir / "run_probe.json", record)

    service_pid = None
    details = lifecycle.extract_details(record.get("stdout_json"))
    if isinstance(details, dict):
        service_pid = details.get("service_pid")
        if process_name is None:
            process_name = details.get("process_name")

    if keepalive_service is not None:
        attach_meta["keepalive"] = {
            "run_id": keepalive_service.config.run_id,
            "events_path": keepalive_events_path,
            "target_id": keepalive_target_id,
            "hook_id": keepalive_hook_id,
            "hook_record": keepalive_hook_record,
            "error": keepalive_error,
        }

    if frida_capture is not None:
        attach_meta["service_pid"] = service_pid
        if service_pid is not None and "pid" in attach_meta:
            attach_meta["pid_matches_service_pid"] = str(service_pid) == str(attach_meta["pid"])
        frida_capture.finalize_meta(world_id=world_id, attach_meta=attach_meta)
        frida_capture.close()
    elif keepalive_service is not None and keepalive_hook_id is not None:
        attach_meta["service_pid"] = service_pid
        if service_pid is not None and "pid" in attach_meta:
            attach_meta["pid_matches_service_pid"] = str(service_pid) == str(attach_meta["pid"])
        if keepalive_hook_record and keepalive_hook_record.get("status") == "ready":
            try:
                keepalive_service.client.hook_finalize(hook_id=keepalive_hook_id, attach_meta=attach_meta)
            except keepalive.KeepaliveError as exc:
                keepalive_error = f"{exc.code}: {exc.message}"
                frida_attach_error = frida_attach_error or keepalive_error

    if keepalive_service is not None and keepalive_target_id is not None:
        try:
            keepalive_service.client.release(target_id=keepalive_target_id)
        except keepalive.KeepaliveError as exc:
            keepalive_error = keepalive_error or f"{exc.code}: {exc.message}"
    if keepalive_service is not None:
        keepalive_service.close()

    manifest = {
        "schema_version": 1,
        "world_id": world_id,
        "run_id": run_id,
        "plan_id": args.plan_id,
        "row_id": row_id,
        "out_dir": path_utils.to_repo_relative(out_root, repo_root),
        "probe": {
            "profile_id": args.profile_id,
            "probe_id": args.probe_id,
            "probe_args": list(args.probe_args),
        },
        "witness": {
            "run_probe_path": path_utils.to_repo_relative(witness_dir / "run_probe.json", repo_root),
            "capabilities_snapshot_path": (
                path_utils.to_repo_relative(witness_dir / "capabilities_snapshot.json", repo_root)
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
            "keepalive": (
                {
                    "run_id": keepalive_service.config.run_id,
                    "events_path": keepalive_events_path,
                    "target_id": keepalive_target_id,
                    "hook_id": keepalive_hook_id,
                    "hook_record": keepalive_hook_record,
                    "error": keepalive_error,
                }
                if keepalive_service is not None
                else None
            ),
        },
        "selftest": {
            "path": selftest_path,
            "source": selftest_source,
            "prepared": selftest_prepared,
            "prepare_error": selftest_prepare_error,
        },
    }
    write_json(out_root / "manifest.json", manifest)
    if isinstance(frida_attach_error, str) and (
        frida_attach_error.startswith("ManifestError:")
        or frida_attach_error.startswith("ConfigError:")
        or frida_attach_error.startswith("ConfigureError:")
        or frida_attach_error.startswith("FridaImportError:")
        or frida_attach_error.startswith("KeepaliveError:")
        or frida_attach_error.startswith("keepalive_")
    ):
        return 1
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = build_arg_parser()
    args = ap.parse_args(argv)
    return run_from_args(args)


if __name__ == "__main__":
    raise SystemExit(main())
