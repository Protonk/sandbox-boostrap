"""Scenario runners for EntitlementJail 1.x (entitlement-diff experiment)."""

from __future__ import annotations

import socket
import threading
import os
import shutil
import stat
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from book.api import path_utils
from book.api.entitlementjail.cli import (
    EJ,
    REPO_ROOT,
    WORLD_ID,
    bundle_evidence,
    extract_profile_bundle_id,
    extract_file_path,
    extract_stdout_text,
    extract_tmp_dir,
    maybe_parse_json,
    parse_probe_catalog,
    run_cmd,
    run_matrix_group,
    run_xpc,
)
from book.api.entitlementjail.logging import LOG_OBSERVER_LAST, observer_status
from book.api.entitlementjail.protocol import normalize_wait_spec, trigger_wait_path
from book.api.entitlementjail.session import XpcSession
from ej_profiles import MATRIX_GROUPS, PROFILES

OUT_ROOT = REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "out" / "ej"
LOG_DIR = OUT_ROOT / "logs"
MATRIX_DIR = OUT_ROOT / "matrix"
EVIDENCE_DIR = OUT_ROOT / "evidence" / "latest"

PLAN_ID = "entitlement-diff:ej"


def _log_path(prefix: str, profile_label: str, probe_id: str) -> Path:
    return LOG_DIR / f"{prefix}.{profile_label}.{probe_id}.log"


def _copy_tree(src: Path, dest: Path) -> Optional[str]:
    if not src.exists():
        return f"source_missing: {src}"
    dest.mkdir(parents=True, exist_ok=True)
    try:
        for path in src.iterdir():
            if path.is_dir():
                shutil.copytree(path, dest / path.name, dirs_exist_ok=True)
            else:
                shutil.copy2(path, dest / path.name)
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"
    return None


def _stdout_jsonl_kinds(events: List[Dict[str, object]]) -> Dict[str, int]:
    kinds: Dict[str, int] = {}
    for obj in events:
        kind = obj.get("kind") if isinstance(obj, dict) else None
        if isinstance(kind, str):
            kinds[kind] = kinds.get(kind, 0) + 1
    return kinds


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


def _extract_wait_spec_from_probe_args(probe_args: List[str]) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
    fifo_path = _extract_flag_value(probe_args, "--wait-fifo")
    if fifo_path is not None:
        return fifo_path, "fifo", _extract_flag_int(probe_args, "--wait-timeout-ms"), _extract_flag_int(probe_args, "--wait-interval-ms")
    exists_path = _extract_flag_value(probe_args, "--wait-exists")
    if exists_path is not None:
        return exists_path, "exists", _extract_flag_int(probe_args, "--wait-timeout-ms"), _extract_flag_int(probe_args, "--wait-interval-ms")
    return None, None, _extract_flag_int(probe_args, "--wait-timeout-ms"), _extract_flag_int(probe_args, "--wait-interval-ms")


def run_wait_xpc(
    *,
    profile_id: Optional[str] = None,
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
    if not profile_id:
        raise ValueError("profile_id is required for run_wait_xpc")

    normalized_wait_spec = normalize_wait_spec(wait_spec)
    started_at_unix_s = time.time()
    record: Dict[str, object] = {
        "profile_id": profile_id,
        "probe_id": probe_id,
        "probe_args": list(probe_args),
        "plan_id": plan_id,
        "row_id": row_id,
        "correlation_id": correlation_id,
        "wait_spec": normalized_wait_spec,
        "wait_timeout_ms": wait_timeout_ms,
        "wait_interval_ms": wait_interval_ms,
        "xpc_timeout_ms": xpc_timeout_ms,
        "ack_risk": ack_risk,
        "trigger_delay_s": trigger_delay_s,
        "post_trigger": post_trigger,
        "post_trigger_delay_s": post_trigger_delay_s,
    }

    session = XpcSession(
        profile_id=profile_id,
        plan_id=plan_id,
        correlation_id=correlation_id,
        ack_risk=ack_risk,
        wait_spec=normalized_wait_spec,
        wait_timeout_ms=wait_timeout_ms,
        wait_interval_ms=wait_interval_ms,
        xpc_timeout_ms=xpc_timeout_ms,
    )

    try:
        session.start(ready_timeout_s=wait_ready_timeout_s)
    except Exception as exc:
        finished_at_unix_s = time.time()
        record.update(
            {
                "command": session.command(),
                "error": f"{type(exc).__name__}: {exc}",
                "session_error": session.last_error,
                "started_at_unix_s": started_at_unix_s,
                "finished_at_unix_s": finished_at_unix_s,
                "duration_s": finished_at_unix_s - started_at_unix_s,
            }
        )
        return record

    wait_info: Dict[str, object] = {}
    trigger_events: List[Dict[str, object]] = []
    probe_record: Dict[str, object] = {}

    try:
        if session.session_ready and isinstance(session.session_ready.get("data"), dict):
            wait_info["session_ready"] = session.session_ready.get("data")
        if session.wait_ready and isinstance(session.wait_ready.get("data"), dict):
            wait_info["wait_ready"] = session.wait_ready.get("data")

        wait_path = session.wait_path()
        wait_mode = session.wait_mode()
        wait_info["wait_path"] = wait_path
        wait_info["wait_mode"] = wait_mode
        wait_info["wait_timeout_ms"] = wait_timeout_ms
        wait_info["wait_interval_ms"] = wait_interval_ms

        if on_wait_ready is not None and wait_path and wait_mode:
            try:
                on_wait_ready(
                    {
                        "wait_path": wait_path,
                        "wait_mode": wait_mode,
                        "wait_timeout_ms": wait_timeout_ms,
                        "session_ready": wait_info.get("session_ready"),
                        "wait_ready": wait_info.get("wait_ready"),
                    }
                )
                wait_info["on_wait_ready_called"] = True
            except Exception as exc:
                wait_info["on_wait_ready_error"] = f"{type(exc).__name__}: {exc}"

        if wait_path and wait_mode:
            if trigger_delay_s > 0:
                time.sleep(trigger_delay_s)
            trigger_at = time.time()
            trigger_error = session.trigger_wait(nonblocking=False, timeout_s=2.0)
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
                post_error = session.trigger_wait(nonblocking=True, timeout_s=0.0)
                trigger_events.append({"kind": "post", "at_unix_s": post_at, "error": post_error})

            if trigger_error is None:
                trigger_event = session.wait_for_trigger_received(timeout_s=2.0)
                if trigger_event and isinstance(trigger_event.get("data"), dict):
                    wait_info["trigger_received"] = trigger_event.get("data")

        probe_timeout_s = process_timeout_s or 25.0
        probe_record = session.run_probe_with_observer(
            probe_id=probe_id,
            argv=probe_args,
            timeout_s=probe_timeout_s,
            log_path=log_path,
            plan_id=plan_id,
            row_id=row_id,
            observer_last=LOG_OBSERVER_LAST,
            write_probe_log=False,
        )
    finally:
        session.close()

    finished_at_unix_s = time.time()
    stdout_text = "".join(session.stdout_lines).rstrip()
    stderr_text = "".join(session.stderr_lines).rstrip()

    log_write_error = None
    if log_path is not None and stdout_text:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(stdout_text + "\n")
        except Exception as exc:
            log_write_error = f"{type(exc).__name__}: {exc}"

    record.update(
        {
            "command": session.command(),
            "exit_code": session.exit_code,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "log_path": path_utils.to_repo_relative(log_path, REPO_ROOT) if log_path else None,
            "log_write_error": log_write_error,
            "observer": probe_record.get("observer"),
            "observer_log_path": probe_record.get("observer_log_path"),
            "observer_status": probe_record.get("observer_status"),
            "wait_info": wait_info,
            "trigger_events": trigger_events,
            "probe_started_at_unix_s": probe_record.get("probe_started_at_unix_s"),
            "probe_finished_at_unix_s": probe_record.get("probe_finished_at_unix_s"),
            "probe_timeout_s": probe_record.get("probe_timeout_s"),
            "probe_error": probe_record.get("probe_error"),
            "started_at_unix_s": started_at_unix_s,
            "finished_at_unix_s": finished_at_unix_s,
            "duration_s": finished_at_unix_s - started_at_unix_s,
            "stdout_jsonl_kinds": _stdout_jsonl_kinds(session.stdout_jsonl),
        }
    )
    if "stdout_json" in probe_record:
        record["stdout_json"] = probe_record["stdout_json"]
    else:
        record["stdout_json_error"] = probe_record.get("stdout_json_error", "probe_response_missing")
    return record


def run_probe_wait(
    *,
    profile_id: Optional[str] = None,
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
    if not profile_id:
        raise ValueError("profile_id is required for run_probe_wait")

    wait_path, wait_mode, wait_timeout_ms, wait_interval_ms = _extract_wait_spec_from_probe_args(probe_args)
    started_at_unix_s = time.time()
    record: Dict[str, object] = {
        "profile_id": profile_id,
        "probe_id": probe_id,
        "probe_args": list(probe_args),
        "plan_id": plan_id,
        "row_id": row_id,
        "correlation_id": correlation_id,
        "ack_risk": ack_risk,
        "xpc_timeout_ms": xpc_timeout_ms,
        "trigger_delay_s": trigger_delay_s,
    }

    session = XpcSession(
        profile_id=profile_id,
        plan_id=plan_id,
        correlation_id=correlation_id,
        ack_risk=ack_risk,
        wait_spec=None,
        xpc_timeout_ms=xpc_timeout_ms,
    )

    try:
        session.start(ready_timeout_s=wait_ready_timeout_s)
    except Exception as exc:
        finished_at_unix_s = time.time()
        record.update(
            {
                "command": session.command(),
                "error": f"{type(exc).__name__}: {exc}",
                "session_error": session.last_error,
                "started_at_unix_s": started_at_unix_s,
                "finished_at_unix_s": finished_at_unix_s,
                "duration_s": finished_at_unix_s - started_at_unix_s,
            }
        )
        return record

    wait_info: Dict[str, object] = {
        "wait_args_source": "probe_args",
        "wait_path": wait_path,
        "wait_mode": wait_mode,
        "wait_timeout_ms": wait_timeout_ms,
        "wait_interval_ms": wait_interval_ms,
    }
    trigger_events: List[Dict[str, object]] = []
    probe_response: Optional[Dict[str, object]] = None
    observer: Optional[Dict[str, object]] = None
    observer_log_path = None
    probe_started_at_unix_s = time.time()
    probe_finished_at_unix_s = probe_started_at_unix_s

    try:
        if session.session_ready and isinstance(session.session_ready.get("data"), dict):
            wait_info["session_ready"] = session.session_ready.get("data")

        if on_wait_ready is not None and wait_path and wait_mode:
            try:
                on_wait_ready({"wait_path": wait_path, "wait_mode": wait_mode, "wait_timeout_ms": wait_timeout_ms})
                wait_info["on_wait_ready_called"] = True
            except Exception as exc:
                wait_info["on_wait_ready_error"] = f"{type(exc).__name__}: {exc}"

        try:
            session.send_command({"command": "run_probe", "probe_id": probe_id, "argv": list(probe_args)})
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
                trigger_error = trigger_wait_path(
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
                post_error = trigger_wait_path(
                    wait_path=wait_path,
                    wait_mode=wait_mode,
                    nonblocking=True,
                    timeout_s=0.0,
                )
                trigger_events.append({"kind": "post", "at_unix_s": post_at, "error": post_error})
                post_trigger_scheduled_at = None

            obj = session.read_jsonl(timeout_s=0.2)
            if obj is None:
                if session.proc is not None and session.proc.poll() is not None:
                    break
                continue
            if obj.get("kind") == "probe_response":
                probe_response = obj
                break

        probe_finished_at_unix_s = time.time()

        observer, observer_log_path = session.capture_observer(
            probe_response=probe_response,
            log_path=log_path,
            plan_id=plan_id,
            row_id=row_id,
            observer_last=LOG_OBSERVER_LAST,
            start_s=probe_started_at_unix_s,
            end_s=probe_finished_at_unix_s,
        )
    finally:
        session.close()

    finished_at_unix_s = time.time()
    stdout_text = "".join(session.stdout_lines).rstrip()
    stderr_text = "".join(session.stderr_lines).rstrip()

    log_write_error = None
    if log_path is not None and stdout_text:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(stdout_text + "\n")
        except Exception as exc:
            log_write_error = f"{type(exc).__name__}: {exc}"

    record.update(
        {
            "command": session.command(),
            "exit_code": session.exit_code,
            "stdout": stdout_text,
            "stderr": stderr_text,
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
            "finished_at_unix_s": finished_at_unix_s,
            "duration_s": finished_at_unix_s - started_at_unix_s,
            "stdout_jsonl_kinds": _stdout_jsonl_kinds(session.stdout_jsonl),
        }
    )

    if probe_response is not None:
        record["stdout_json"] = probe_response
    else:
        record["stdout_json_error"] = "probe_response_missing"
    return record


def _run_tcp_listener(host: str = "127.0.0.1", timeout_s: float = 2.0) -> Tuple[Dict[str, object], callable]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    state: Dict[str, object] = {"host": host, "port": port, "accepted": False, "error": None}

    def _accept_once() -> None:
        try:
            sock.settimeout(timeout_s)
            conn, _ = sock.accept()
            conn.close()
            state["accepted"] = True
        except socket.timeout:
            state["error"] = "timeout"
        except Exception as exc:
            state["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            sock.close()

    thread = threading.Thread(target=_accept_once, daemon=True)
    thread.start()

    def _finish() -> Dict[str, object]:
        thread.join(timeout=timeout_s + 0.5)
        if thread.is_alive():
            state["error"] = "accept_timeout"
        return state

    return state, _finish


def _supports_probe(stdout_json: Optional[Dict[str, object]], probe_id: str) -> bool:
    catalog = parse_probe_catalog(stdout_json)
    if not isinstance(catalog, dict):
        return False
    probe_ids = catalog.get("probe_ids")
    return bool(isinstance(probe_ids, list) and probe_id in probe_ids)


def _capture_tmp_dir(
    profile: object,
    *,
    tag: str,
    ack_risk: Optional[str],
    runs: List[Dict[str, object]],
) -> Optional[str]:
    snapshot = run_xpc(
        profile_id=profile.profile_id,
        probe_id="capabilities_snapshot",
        probe_args=[],
        log_path=_log_path(tag, profile.label, "capabilities_snapshot"),
        plan_id=PLAN_ID,
        row_id=f"{tag}.{profile.label}.capabilities_snapshot",
        ack_risk=ack_risk,
    )
    runs.append(snapshot)
    return extract_tmp_dir(snapshot.get("stdout_json"))


def scenario_inventory() -> Dict[str, Dict[str, object]]:
    commands = [
        run_cmd([str(EJ), "health-check"]),
        run_cmd([str(EJ), "list-profiles"]),
        run_cmd([str(EJ), "list-services"]),
    ]
    for profile in PROFILES.values():
        commands.append(run_cmd([str(EJ), "show-profile", profile.profile_id]))
        commands.append(run_cmd([str(EJ), "describe-service", profile.profile_id]))

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "kind": "inventory",
        "commands": commands,
    }
    return {"inventory": payload}


def scenario_evidence(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    commands = [
        run_cmd([str(EJ), "verify-evidence"]),
        run_cmd([str(EJ), "inspect-macho", "main"]),
        run_cmd([str(EJ), "inspect-macho", "evidence.symbols"]),
        run_cmd([str(EJ), "inspect-macho", "evidence.profiles"]),
    ]
    for profile in PROFILES.values():
        commands.append(run_cmd([str(EJ), "inspect-macho", profile.service_id]))

    bundle_record = bundle_evidence(ack_risk=ack_risk, dest_dir=EVIDENCE_DIR)

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "kind": "evidence",
        "commands": commands,
        "bundle": bundle_record,
    }
    return {"evidence": payload}


def scenario_matrix_groups(
    *,
    groups: Optional[Sequence[str]],
    ack_risk: Optional[str],
) -> Dict[str, Dict[str, object]]:
    group_list = list(groups) if groups else list(MATRIX_GROUPS)
    records: Dict[str, object] = {}
    for group in group_list:
        records[group] = run_matrix_group(group, ack_risk=ack_risk, dest_dir=MATRIX_DIR / group)

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "kind": "matrix_groups",
        "groups": records,
    }
    return {"matrix": payload}


def scenario_bookmarks(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    runs: List[Dict[str, object]] = []
    tmp_dirs: Dict[str, Optional[str]] = {}
    catalog_payloads: Dict[str, Optional[Dict[str, object]]] = {}

    for profile in [PROFILES["minimal"], PROFILES["bookmarks_app_scope"]]:
        for probe_id in ["capabilities_snapshot", "world_shape", "probe_catalog"]:
            record = run_xpc(
                profile_id=profile.profile_id,
                probe_id=probe_id,
                probe_args=[],
                log_path=_log_path("bookmarks", profile.label, probe_id),
                plan_id=PLAN_ID,
                row_id=f"bookmarks.{profile.label}.{probe_id}",
                ack_risk=ack_risk,
            )
            runs.append(record)
            if probe_id == "capabilities_snapshot":
                tmp_dirs[profile.profile_id] = extract_tmp_dir(record.get("stdout_json"))
            if probe_id == "probe_catalog":
                catalog_payloads[profile.profile_id] = record.get("stdout_json")

    supports_bookmark_make = _supports_probe(catalog_payloads.get(PROFILES["bookmarks_app_scope"].profile_id), "bookmark_make")
    bookmark_targets: Dict[str, Optional[str]] = {}

    if supports_bookmark_make:
        for profile in [PROFILES["minimal"], PROFILES["bookmarks_app_scope"]]:
            tmp_dir = tmp_dirs.get(profile.profile_id)
            if tmp_dir is None:
                bookmark_targets[profile.profile_id] = None
                continue
            target_path = str(Path(tmp_dir) / "ej_bookmark_target.txt")
            bookmark_targets[profile.profile_id] = target_path
            runs.append(
                run_xpc(
                    profile_id=profile.profile_id,
                    probe_id="fs_op",
                    probe_args=["--op", "create", "--path", target_path, "--allow-unsafe-path"],
                    log_path=_log_path("bookmarks", profile.label, "fs_create"),
                    plan_id=PLAN_ID,
                    row_id=f"bookmarks.{profile.label}.fs_create",
                    ack_risk=ack_risk,
                )
            )
            runs.append(
                run_xpc(
                    profile_id=profile.profile_id,
                    probe_id="bookmark_make",
                    probe_args=["--path", target_path],
                    log_path=_log_path("bookmarks", profile.label, "bookmark_make"),
                    plan_id=PLAN_ID,
                    row_id=f"bookmarks.{profile.label}.bookmark_make",
                    ack_risk=ack_risk,
                )
            )

        bookmark_b64 = None
        for record in runs:
            if record.get("profile_id") != PROFILES["bookmarks_app_scope"].profile_id:
                continue
            if record.get("probe_id") != "bookmark_make":
                continue
            bookmark_b64 = extract_stdout_text(record.get("stdout_json"))
            break

        if bookmark_b64:
            runs.append(
                run_xpc(
                    profile_id=PROFILES["bookmarks_app_scope"].profile_id,
                    probe_id="bookmark_op",
                    probe_args=["--bookmark-b64", bookmark_b64, "--op", "stat"],
                    log_path=_log_path("bookmarks", "bookmarks_app_scope", "bookmark_op_stat"),
                    plan_id=PLAN_ID,
                    row_id="bookmarks.bookmarks_app_scope.bookmark_op_stat",
                    ack_risk=ack_risk,
                )
            )

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "bookmarks",
        "supports_bookmark_make": supports_bookmark_make,
        "bookmark_targets": bookmark_targets,
        "runs": runs,
    }
    return {"bookmarks": payload}


def scenario_downloads_rw(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    runs: List[Dict[str, object]] = []
    for profile in [PROFILES["minimal"], PROFILES["downloads_rw"]]:
        for probe_id in ["capabilities_snapshot", "world_shape"]:
            runs.append(
                run_xpc(
                    profile_id=profile.profile_id,
                    probe_id=probe_id,
                    probe_args=[],
                    log_path=_log_path("downloads", profile.label, probe_id),
                    plan_id=PLAN_ID,
                    row_id=f"downloads.{profile.label}.{probe_id}",
                    ack_risk=ack_risk,
                )
            )
        runs.append(
            run_xpc(
                profile_id=profile.profile_id,
                probe_id="fs_op",
                probe_args=["--op", "listdir", "--path-class", "downloads"],
                log_path=_log_path("downloads", profile.label, "fs_listdir"),
                plan_id=PLAN_ID,
                row_id=f"downloads.{profile.label}.fs_listdir",
                ack_risk=ack_risk,
            )
        )

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "downloads_rw",
        "runs": runs,
    }
    return {"downloads_rw": payload}


def scenario_net_client(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    runs: List[Dict[str, object]] = []
    host = "127.0.0.1"

    for profile in [PROFILES["minimal"], PROFILES["net_client"]]:
        for probe_id in ["capabilities_snapshot", "world_shape"]:
            runs.append(
                run_xpc(
                    profile_id=profile.profile_id,
                    probe_id=probe_id,
                    probe_args=[],
                    log_path=_log_path("net_client", profile.label, probe_id),
                    plan_id=PLAN_ID,
                    row_id=f"net_client.{profile.label}.{probe_id}",
                    ack_risk=ack_risk,
                )
            )

        listener_state, finish_listener = _run_tcp_listener(host=host, timeout_s=2.0)
        record = run_xpc(
            profile_id=profile.profile_id,
            probe_id="net_op",
            probe_args=["--op", "tcp_connect", "--host", host, "--port", str(listener_state["port"])],
            log_path=_log_path("net_client", profile.label, "tcp_connect"),
            plan_id=PLAN_ID,
            row_id=f"net_client.{profile.label}.tcp_connect",
            ack_risk=ack_risk,
        )
        record["listener"] = finish_listener()
        runs.append(record)

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "net_client",
        "net_op": {"op": "tcp_connect", "host": host, "port": "dynamic"},
        "runs": runs,
    }
    return {"net_client": payload}


def _list_probe_profiles() -> Tuple[Dict[str, object], List[Dict[str, object]]]:
    result = run_cmd([str(EJ), "list-profiles"])
    stdout_json = maybe_parse_json(result.get("stdout", "").strip())
    profiles: List[Dict[str, object]] = []
    if isinstance(stdout_json, dict):
        data = stdout_json.get("data")
        if isinstance(data, dict):
            for profile in data.get("profiles", []):
                if isinstance(profile, dict) and profile.get("kind") == "probe":
                    profiles.append(profile)
    result["stdout_json"] = stdout_json
    return result, profiles


def scenario_net_op_groups(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    runs: List[Dict[str, object]] = []
    host = "127.0.0.1"
    list_profiles, profiles = _list_probe_profiles()

    for profile in profiles:
        profile_id = profile.get("profile_id")
        bundle_id = profile.get("bundle_id")
        if not isinstance(profile_id, str) or not isinstance(bundle_id, str):
            continue
        risk_tier = profile.get("risk_tier")
        profile_ack = profile_id if risk_tier == 2 else ack_risk

        listener_state, finish_listener = _run_tcp_listener(host=host, timeout_s=2.0)
        record = run_xpc(
            profile_id=profile_id,
            probe_id="net_op",
            probe_args=["--op", "tcp_connect", "--host", host, "--port", str(listener_state["port"])],
            log_path=_log_path("net_op_groups", profile_id, "tcp_connect"),
            plan_id=PLAN_ID,
            row_id=f"net_op_groups.{profile_id}.tcp_connect",
            ack_risk=profile_ack,
        )
        record["listener"] = finish_listener()
        record["profile_tags"] = profile.get("tags")
        record["risk_tier"] = risk_tier
        runs.append(record)

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "net_op_groups",
        "net_op": {"op": "tcp_connect", "host": host, "port": "dynamic"},
        "profiles": profiles,
        "list_profiles": list_profiles,
        "runs": runs,
    }
    return {"net_op_groups": payload}


def _run_userdefaults(profile, *, ack_risk: Optional[str]) -> List[Dict[str, object]]:
    runs = []
    for op in ["write", "read", "remove"]:
        args: List[str] = ["--op", op, "--key", "ej_ud_key"]
        if op == "write":
            args += ["--value", "1"]
        runs.append(
            run_xpc(
                profile_id=profile.profile_id,
                probe_id="userdefaults_op",
                probe_args=args,
                log_path=_log_path("userdefaults", profile.label, op),
                plan_id=PLAN_ID,
                row_id=f"userdefaults.{profile.label}.{op}",
                ack_risk=ack_risk,
            )
        )
    return runs


def _run_fs_xattr(profile, *, ack_risk: Optional[str]) -> Tuple[List[Dict[str, object]], Optional[str]]:
    runs: List[Dict[str, object]] = []
    snapshot = run_xpc(
        profile_id=profile.profile_id,
        probe_id="capabilities_snapshot",
        probe_args=[],
        log_path=_log_path("fs_xattr", profile.label, "capabilities_snapshot"),
        plan_id=PLAN_ID,
        row_id=f"fs_xattr.{profile.label}.capabilities_snapshot",
        ack_risk=ack_risk,
    )
    runs.append(snapshot)
    tmp_dir = extract_tmp_dir(snapshot.get("stdout_json"))
    if not tmp_dir:
        return runs, None

    file_path = str(Path(tmp_dir) / "ej_xattr.txt")
    create = run_xpc(
        profile_id=profile.profile_id,
        probe_id="fs_op",
        probe_args=["--op", "create", "--path", file_path, "--allow-unsafe-path"],
        log_path=_log_path("fs_xattr", profile.label, "fs_create"),
        plan_id=PLAN_ID,
        row_id=f"fs_xattr.{profile.label}.fs_create",
        ack_risk=ack_risk,
    )
    runs.append(create)
    created_path = extract_file_path(create.get("stdout_json")) or file_path

    for op, args in [
        (
            "set",
            [
                "--op",
                "set",
                "--path",
                created_path,
                "--name",
                "user.ej_test",
                "--value",
                "ej_probe",
                "--allow-write",
            ],
        ),
        ("get", ["--op", "get", "--path", created_path, "--name", "user.ej_test"]),
        ("list", ["--op", "list", "--path", created_path]),
    ]:
        runs.append(
            run_xpc(
                profile_id=profile.profile_id,
                probe_id="fs_xattr",
                probe_args=args,
                log_path=_log_path("fs_xattr", profile.label, op),
                plan_id=PLAN_ID,
                row_id=f"fs_xattr.{profile.label}.{op}",
                ack_risk=ack_risk,
            )
        )

    return runs, created_path


def _run_fs_coordinated(profile, *, ack_risk: Optional[str]) -> List[Dict[str, object]]:
    runs: List[Dict[str, object]] = []
    for op in ["read", "write"]:
        runs.append(
            run_xpc(
                profile_id=profile.profile_id,
                probe_id="fs_coordinated_op",
                probe_args=["--op", op, "--path-class", "tmp", "--target", "run_dir"],
                log_path=_log_path("fs_coord", profile.label, op),
                plan_id=PLAN_ID,
                row_id=f"fs_coord.{profile.label}.{op}",
                ack_risk=ack_risk,
            )
        )
    return runs


def scenario_probe_families(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    userdefaults_runs: List[Dict[str, object]] = []
    fs_runs: List[Dict[str, object]] = []
    xattr_targets: Dict[str, Optional[str]] = {}

    for profile in [PROFILES["minimal"], PROFILES["downloads_rw"]]:
        userdefaults_runs.extend(_run_userdefaults(profile, ack_risk=ack_risk))

        xattr_runs, xattr_target = _run_fs_xattr(profile, ack_risk=ack_risk)
        fs_runs.extend(xattr_runs)
        xattr_targets[profile.profile_id] = xattr_target

        fs_runs.extend(_run_fs_coordinated(profile, ack_risk=ack_risk))

    payload_userdefaults = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "userdefaults_op",
        "runs": userdefaults_runs,
    }
    payload_fs = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "filesystem_probes",
        "xattr_targets": xattr_targets,
        "runs": fs_runs,
    }
    return {
        "probes_userdefaults": payload_userdefaults,
        "probes_filesystem": payload_fs,
    }


def scenario_bookmark_roundtrip(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    runs: List[Dict[str, object]] = []
    tmp_dirs: Dict[str, Optional[str]] = {}
    catalog_payloads: Dict[str, Optional[Dict[str, object]]] = {}

    for profile in [PROFILES["minimal"], PROFILES["bookmarks_app_scope"]]:
        record = run_xpc(
            profile_id=profile.profile_id,
            probe_id="capabilities_snapshot",
            probe_args=[],
            log_path=_log_path("bookmark_roundtrip", profile.label, "capabilities_snapshot"),
            plan_id=PLAN_ID,
            row_id=f"bookmark_roundtrip.{profile.label}.capabilities_snapshot",
            ack_risk=ack_risk,
        )
        runs.append(record)
        tmp_dirs[profile.profile_id] = extract_tmp_dir(record.get("stdout_json"))

        catalog = run_xpc(
            profile_id=profile.profile_id,
            probe_id="probe_catalog",
            probe_args=[],
            log_path=_log_path("bookmark_roundtrip", profile.label, "probe_catalog"),
            plan_id=PLAN_ID,
            row_id=f"bookmark_roundtrip.{profile.label}.probe_catalog",
            ack_risk=ack_risk,
        )
        runs.append(catalog)
        catalog_payloads[profile.profile_id] = catalog.get("stdout_json")

    supports_roundtrip = _supports_probe(
        catalog_payloads.get(PROFILES["bookmarks_app_scope"].profile_id),
        "bookmark_roundtrip",
    )
    targets: Dict[str, Optional[str]] = {}

    if supports_roundtrip:
        for profile in [PROFILES["minimal"], PROFILES["bookmarks_app_scope"]]:
            tmp_dir = tmp_dirs.get(profile.profile_id)
            if tmp_dir is None:
                targets[profile.profile_id] = None
                continue
            target_path = str(Path(tmp_dir) / "ej_roundtrip_target.txt")
            targets[profile.profile_id] = target_path
            runs.append(
                run_xpc(
                    profile_id=profile.profile_id,
                    probe_id="fs_op",
                    probe_args=["--op", "create", "--path", target_path, "--allow-unsafe-path"],
                    log_path=_log_path("bookmark_roundtrip", profile.label, "fs_create"),
                    plan_id=PLAN_ID,
                    row_id=f"bookmark_roundtrip.{profile.label}.fs_create",
                    ack_risk=ack_risk,
                )
            )
            runs.append(
                run_xpc(
                    profile_id=profile.profile_id,
                    probe_id="bookmark_roundtrip",
                    probe_args=["--path", target_path, "--op", "stat"],
                    log_path=_log_path("bookmark_roundtrip", profile.label, "roundtrip_stat"),
                    plan_id=PLAN_ID,
                    row_id=f"bookmark_roundtrip.{profile.label}.roundtrip_stat",
                    ack_risk=ack_risk,
                )
            )

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "bookmark_roundtrip",
        "supports_bookmark_roundtrip": supports_roundtrip,
        "targets": targets,
        "runs": runs,
    }
    return {"bookmark_roundtrip": payload}


def scenario_wait_attach(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    profile = PROFILES["minimal"]
    runs: List[Dict[str, object]] = []

    snapshot = run_xpc(
        profile_id=profile.profile_id,
        probe_id="capabilities_snapshot",
        probe_args=[],
        log_path=_log_path("wait_attach", profile.label, "capabilities_snapshot"),
        plan_id=PLAN_ID,
        row_id="wait_attach.minimal.capabilities_snapshot",
        ack_risk=ack_risk,
    )
    runs.append(snapshot)
    tmp_dir = extract_tmp_dir(snapshot.get("stdout_json"))

    runs.append(
        run_wait_xpc(
            profile_id=profile.profile_id,
            probe_id="probe_catalog",
            probe_args=[],
            wait_spec="fifo:auto",
            wait_timeout_ms=15000,
            log_path=_log_path("wait_attach", profile.label, "attach_fifo"),
            plan_id=PLAN_ID,
            row_id="wait_attach.minimal.attach_fifo",
            ack_risk=ack_risk,
        )
    )

    if tmp_dir:
        fifo_path = Path(tmp_dir) / "ej_wait_attach.fifo"
        try:
            if fifo_path.exists():
                fifo_path.unlink()
            os.mkfifo(fifo_path)
            fifo_error = None
        except Exception as exc:
            fifo_error = f"{type(exc).__name__}: {exc}"
        runs.append(
            {
                "profile_id": profile.profile_id,
                "probe_id": "fs_op_wait",
                "probe_args": [],
                "row_id": "wait_attach.minimal.wait_fifo_prep",
                "fifo_path": str(fifo_path),
                "fifo_error": fifo_error,
            }
        )
        if fifo_error is None:
            runs.append(
                run_wait_xpc(
                    profile_id=profile.profile_id,
                    probe_id="fs_op",
                    probe_args=["--op", "stat", "--path-class", "tmp"],
                    wait_spec=f"fifo:{fifo_path}",
                    wait_timeout_ms=15000,
                    log_path=_log_path("wait_attach", profile.label, "wait_fifo"),
                    plan_id=PLAN_ID,
                    row_id="wait_attach.minimal.wait_fifo",
                    ack_risk=ack_risk,
                )
            )

        trigger_path = Path(tmp_dir) / "ej_wait_exists.trigger"
        try:
            if trigger_path.exists():
                trigger_path.unlink()
            exists_error = None
        except Exception as exc:
            exists_error = f"{type(exc).__name__}: {exc}"
        runs.append(
            {
                "profile_id": profile.profile_id,
                "probe_id": "fs_op_wait",
                "probe_args": [],
                "row_id": "wait_attach.minimal.wait_exists_prep",
                "wait_exists_path": str(trigger_path),
                "wait_exists_error": exists_error,
            }
        )
        if exists_error is None:
            runs.append(
                run_wait_xpc(
                    profile_id=profile.profile_id,
                    probe_id="fs_op",
                    probe_args=["--op", "stat", "--path-class", "tmp"],
                    wait_spec=f"exists:{trigger_path}",
                    wait_timeout_ms=15000,
                    log_path=_log_path("wait_attach", profile.label, "wait_exists"),
                    plan_id=PLAN_ID,
                    row_id="wait_attach.minimal.wait_exists",
                    ack_risk=ack_risk,
                )
            )

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "wait_attach",
        "tmp_dir": tmp_dir,
        "runs": runs,
    }
    return {"wait_attach": payload}


def scenario_wait_timeout_matrix(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    profile = PROFILES["minimal"]
    runs: List[Dict[str, object]] = []
    tmp_dir = _capture_tmp_dir(profile, tag="wait_timeout", ack_risk=ack_risk, runs=runs)

    cases = [
        {"case_id": "t150_fast", "wait_timeout_ms": 150, "trigger_delay_s": 0.05},
        {"case_id": "t150_slow", "wait_timeout_ms": 150, "trigger_delay_s": 0.3},
        {"case_id": "t500_fast", "wait_timeout_ms": 500, "trigger_delay_s": 0.1},
        {"case_id": "t500_slow", "wait_timeout_ms": 500, "trigger_delay_s": 0.9},
    ]

    if tmp_dir:
        base = Path(tmp_dir)
        for case in cases:
            wait_path = base / f"ej_wait_timeout_{case['case_id']}.trigger"
            wait_error = None
            try:
                if wait_path.exists():
                    wait_path.unlink()
            except Exception as exc:
                wait_error = f"{type(exc).__name__}: {exc}"
            if wait_error is not None:
                runs.append(
                    {
                        "case_id": case["case_id"],
                        "wait_path": str(wait_path),
                        "wait_path_error": wait_error,
                    }
                )
                continue

            record = run_wait_xpc(
                profile_id=profile.profile_id,
                probe_id="probe_catalog",
                probe_args=[],
                wait_spec=f"exists:{wait_path}",
                wait_timeout_ms=case["wait_timeout_ms"],
                log_path=_log_path("wait_timeout", profile.label, case["case_id"]),
                plan_id=PLAN_ID,
                row_id=f"wait_timeout.{profile.label}.{case['case_id']}",
                trigger_delay_s=case["trigger_delay_s"],
                wait_ready_timeout_s=10.0,
                ack_risk=ack_risk,
            )
            record["case_id"] = case["case_id"]
            record["case"] = case
            runs.append(record)

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "wait_timeout_matrix",
        "tmp_dir": tmp_dir,
        "cases": cases,
        "runs": runs,
    }
    return {"wait_timeout_matrix": payload}


def scenario_wait_path_class(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    profile = PROFILES["minimal"]
    runs: List[Dict[str, object]] = []
    tmp_dir = _capture_tmp_dir(profile, tag="wait_path_class", ack_risk=ack_risk, runs=runs)

    wait_spec = "fifo:auto"
    wait_timeout_ms = 10000

    runs.append(
        run_wait_xpc(
            profile_id=profile.profile_id,
            probe_id="probe_catalog",
            probe_args=[],
            wait_spec=wait_spec,
            wait_timeout_ms=wait_timeout_ms,
            log_path=_log_path("wait_path_class", profile.label, "path_class"),
            plan_id=PLAN_ID,
            row_id="wait_path_class.minimal.path_class",
            trigger_delay_s=0.1,
            wait_ready_timeout_s=10.0,
            ack_risk=ack_risk,
        )
    )

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "wait_path_class",
        "tmp_dir": tmp_dir,
        "wait_spec": wait_spec,
        "wait_timeout_ms": wait_timeout_ms,
        "runs": runs,
    }
    return {"wait_path_class": payload}


def scenario_wait_multi_trigger(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    profile = PROFILES["minimal"]
    runs: List[Dict[str, object]] = []
    tmp_dir = _capture_tmp_dir(profile, tag="wait_multi", ack_risk=ack_risk, runs=runs)

    if tmp_dir:
        base = Path(tmp_dir)
        fifo_path = base / "ej_wait_multi.fifo"
        fifo_error = None
        try:
            if fifo_path.exists():
                fifo_path.unlink()
            os.mkfifo(fifo_path)
        except Exception as exc:
            fifo_error = f"{type(exc).__name__}: {exc}"
        runs.append(
            {
                "profile_id": profile.profile_id,
                "probe_id": "wait_multi_fifo_prep",
                "row_id": "wait_multi.minimal.fifo_prep",
                "fifo_path": str(fifo_path),
                "fifo_error": fifo_error,
            }
        )
        if fifo_error is None:
            runs.append(
                run_wait_xpc(
                    profile_id=profile.profile_id,
                    probe_id="probe_catalog",
                    probe_args=[],
                    wait_spec=f"fifo:{fifo_path}",
                    wait_timeout_ms=15000,
                    log_path=_log_path("wait_multi", profile.label, "fifo"),
                    plan_id=PLAN_ID,
                    row_id="wait_multi.minimal.fifo",
                    trigger_delay_s=0.05,
                    post_trigger=True,
                    post_trigger_delay_s=0.2,
                    wait_ready_timeout_s=10.0,
                    ack_risk=ack_risk,
                )
            )

        exists_path = base / "ej_wait_multi.exists"
        exists_error = None
        try:
            if exists_path.exists():
                exists_path.unlink()
        except Exception as exc:
            exists_error = f"{type(exc).__name__}: {exc}"
        runs.append(
            {
                "profile_id": profile.profile_id,
                "probe_id": "wait_multi_exists_prep",
                "row_id": "wait_multi.minimal.exists_prep",
                "wait_exists_path": str(exists_path),
                "wait_exists_error": exists_error,
            }
        )
        if exists_error is None:
            runs.append(
                run_wait_xpc(
                    profile_id=profile.profile_id,
                    probe_id="probe_catalog",
                    probe_args=[],
                    wait_spec=f"exists:{exists_path}",
                    wait_timeout_ms=15000,
                    log_path=_log_path("wait_multi", profile.label, "exists"),
                    plan_id=PLAN_ID,
                    row_id="wait_multi.minimal.exists",
                    trigger_delay_s=0.05,
                    post_trigger=True,
                    post_trigger_delay_s=0.2,
                    wait_ready_timeout_s=10.0,
                    ack_risk=ack_risk,
                )
            )

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "wait_multi_trigger",
        "tmp_dir": tmp_dir,
        "runs": runs,
    }
    return {"wait_multi_trigger": payload}


def scenario_wait_probe_wait(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    profile = PROFILES["minimal"]
    runs: List[Dict[str, object]] = []
    tmp_dir = _capture_tmp_dir(profile, tag="wait_probe", ack_risk=ack_risk, runs=runs)

    if tmp_dir:
        base = Path(tmp_dir)
        fifo_path = base / "ej_wait_probe.fifo"
        fifo_error = None
        try:
            if fifo_path.exists():
                fifo_path.unlink()
            os.mkfifo(fifo_path)
        except Exception as exc:
            fifo_error = f"{type(exc).__name__}: {exc}"
        runs.append(
            {
                "profile_id": profile.profile_id,
                "probe_id": "wait_probe_fifo_prep",
                "row_id": "wait_probe.minimal.fifo_prep",
                "fifo_path": str(fifo_path),
                "fifo_error": fifo_error,
            }
        )
        if fifo_error is None:
            runs.append(
                run_probe_wait(
                    profile_id=profile.profile_id,
                    probe_id="fs_op_wait",
                    probe_args=[
                        "--op",
                        "stat",
                        "--path-class",
                        "tmp",
                        "--wait-fifo",
                        str(fifo_path),
                        "--wait-timeout-ms",
                        "12000",
                    ],
                    log_path=_log_path("wait_probe", profile.label, "fifo"),
                    plan_id=PLAN_ID,
                    row_id="wait_probe.minimal.fifo",
                    trigger_delay_s=0.1,
                    wait_ready_timeout_s=8.0,
                    ack_risk=ack_risk,
                )
            )

        exists_path = base / "ej_wait_probe.exists"
        exists_error = None
        try:
            if exists_path.exists():
                exists_path.unlink()
        except Exception as exc:
            exists_error = f"{type(exc).__name__}: {exc}"
        runs.append(
            {
                "profile_id": profile.profile_id,
                "probe_id": "wait_probe_exists_prep",
                "row_id": "wait_probe.minimal.exists_prep",
                "wait_exists_path": str(exists_path),
                "wait_exists_error": exists_error,
            }
        )
        if exists_error is None:
            runs.append(
                run_probe_wait(
                    profile_id=profile.profile_id,
                    probe_id="fs_op_wait",
                    probe_args=[
                        "--op",
                        "stat",
                        "--path-class",
                        "tmp",
                        "--wait-exists",
                        str(exists_path),
                        "--wait-timeout-ms",
                        "12000",
                        "--wait-interval-ms",
                        "50",
                    ],
                    log_path=_log_path("wait_probe", profile.label, "exists"),
                    plan_id=PLAN_ID,
                    row_id="wait_probe.minimal.exists",
                    trigger_delay_s=0.1,
                    wait_ready_timeout_s=8.0,
                    ack_risk=ack_risk,
                )
            )

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "wait_probe_wait",
        "tmp_dir": tmp_dir,
        "runs": runs,
    }
    return {"wait_probe_wait": payload}


def scenario_wait_hold_open(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    profile = PROFILES["minimal"]
    runs: List[Dict[str, object]] = []
    tmp_dir = _capture_tmp_dir(profile, tag="wait_hold_open", ack_risk=ack_risk, runs=runs)

    runs.append(
        run_wait_xpc(
            profile_id=profile.profile_id,
            probe_id="probe_catalog",
            probe_args=[],
            wait_spec="fifo:auto",
            wait_timeout_ms=15000,
            log_path=_log_path("wait_hold_open", profile.label, "attach_hold"),
            plan_id=PLAN_ID,
            row_id="wait_hold_open.minimal.attach_hold",
            trigger_delay_s=0.05,
            wait_ready_timeout_s=10.0,
            process_timeout_s=20.0,
            ack_risk=ack_risk,
        )
    )

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "wait_hold_open",
        "tmp_dir": tmp_dir,
        "runs": runs,
    }
    return {"wait_hold_open": payload}


def scenario_wait_create(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    profile = PROFILES["minimal"]
    runs: List[Dict[str, object]] = []
    tmp_dir = _capture_tmp_dir(profile, tag="wait_create", ack_risk=ack_risk, runs=runs)

    fifo_path = None
    prep_error = None
    if tmp_dir:
        fifo_path = Path(tmp_dir) / "ej_wait_create.fifo"
        try:
            if fifo_path.exists():
                fifo_path.unlink()
        except Exception as exc:
            prep_error = f"{type(exc).__name__}: {exc}"

    if fifo_path is None or prep_error is not None:
        runs.append(
            {
                "profile_id": profile.profile_id,
                "probe_id": "wait_create_prep",
                "row_id": "wait_create.minimal.prep",
                "fifo_path": str(fifo_path) if fifo_path else None,
                "prep_error": prep_error or "missing_tmp_dir",
            }
        )
    else:
        record = run_wait_xpc(
            profile_id=profile.profile_id,
            probe_id="probe_catalog",
            probe_args=[],
            wait_spec=f"fifo:{fifo_path}",
            wait_timeout_ms=15000,
            log_path=_log_path("wait_create", profile.label, "wait_create"),
            plan_id=PLAN_ID,
            row_id="wait_create.minimal.wait_create",
            trigger_delay_s=0.1,
            wait_ready_timeout_s=10.0,
            ack_risk=ack_risk,
        )
        fifo_post_exists = False
        fifo_post_is_fifo = None
        fifo_post_error = None
        try:
            fifo_post_exists = fifo_path.exists()
            if fifo_post_exists:
                fifo_post_is_fifo = stat.S_ISFIFO(os.stat(fifo_path).st_mode)
        except Exception as exc:
            fifo_post_error = f"{type(exc).__name__}: {exc}"
        record["fifo_path"] = str(fifo_path)
        record["fifo_post_exists"] = fifo_post_exists
        record["fifo_post_is_fifo"] = fifo_post_is_fifo
        record["fifo_post_error"] = fifo_post_error
        runs.append(record)

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "wait_create",
        "tmp_dir": tmp_dir,
        "runs": runs,
    }
    return {"wait_create": payload}


def scenario_wait_interval(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    profile = PROFILES["minimal"]
    runs: List[Dict[str, object]] = []
    tmp_dir = _capture_tmp_dir(profile, tag="wait_interval", ack_risk=ack_risk, runs=runs)

    cases = [
        {"case_id": "interval_25", "interval_ms": 25},
        {"case_id": "interval_250", "interval_ms": 250},
    ]

    if tmp_dir:
        base = Path(tmp_dir)
        for case in cases:
            wait_path = base / f"ej_wait_interval_{case['case_id']}.trigger"
            wait_error = None
            try:
                if wait_path.exists():
                    wait_path.unlink()
            except Exception as exc:
                wait_error = f"{type(exc).__name__}: {exc}"
            if wait_error is not None:
                runs.append(
                    {
                        "case_id": case["case_id"],
                        "wait_path": str(wait_path),
                        "wait_path_error": wait_error,
                    }
                )
                continue

            record = run_wait_xpc(
                profile_id=profile.profile_id,
                probe_id="probe_catalog",
                probe_args=[],
                wait_spec=f"exists:{wait_path}",
                wait_timeout_ms=2000,
                wait_interval_ms=case["interval_ms"],
                log_path=_log_path("wait_interval", profile.label, case["case_id"]),
                plan_id=PLAN_ID,
                row_id=f"wait_interval.{profile.label}.{case['case_id']}",
                trigger_delay_s=0.1,
                wait_ready_timeout_s=10.0,
                ack_risk=ack_risk,
            )
            record["case_id"] = case["case_id"]
            record["case"] = case
            runs.append(record)

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "wait_interval",
        "tmp_dir": tmp_dir,
        "cases": cases,
        "runs": runs,
    }
    return {"wait_interval": payload}


def scenario_attach_holdopen_default(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    profile = PROFILES["minimal"]
    runs: List[Dict[str, object]] = []
    _ = _capture_tmp_dir(profile, tag="attach_default", ack_risk=ack_risk, runs=runs)

    runs.append(
        run_wait_xpc(
            profile_id=profile.profile_id,
            probe_id="probe_catalog",
            probe_args=[],
            wait_spec="fifo:auto",
            wait_timeout_ms=15000,
            log_path=_log_path("attach_default", profile.label, "attach_default"),
            plan_id=PLAN_ID,
            row_id="attach_default.minimal.attach_default",
            trigger_delay_s=0.1,
            wait_ready_timeout_s=10.0,
            process_timeout_s=15.0,
            ack_risk=ack_risk,
        )
    )
    runs.append(
        run_wait_xpc(
            profile_id=profile.profile_id,
            probe_id="probe_catalog",
            probe_args=[],
            wait_spec="fifo:auto",
            wait_timeout_ms=15000,
            log_path=_log_path("attach_default", profile.label, "attach_hold_open_zero"),
            plan_id=PLAN_ID,
            row_id="attach_default.minimal.attach_hold_open_zero",
            trigger_delay_s=0.1,
            wait_ready_timeout_s=10.0,
            process_timeout_s=15.0,
            ack_risk=ack_risk,
        )
    )

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "attach_holdopen_default",
        "runs": runs,
    }
    return {"attach_holdopen_default": payload}


def scenario_health_check_profile(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    commands: List[Dict[str, object]] = []
    for profile_id in ["minimal", "debuggable"]:
        res = run_cmd([str(EJ), "health-check", "--profile", profile_id])
        res["profile_id"] = profile_id
        commands.append(res)

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "health_check_profile",
        "commands": commands,
    }
    return {"health_check_profile": payload}


def scenario_run_matrix_out(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    runs: List[Dict[str, object]] = []
    out_root = (
        Path.home()
        / "Library"
        / "Containers"
        / "com.yourteam.entitlement-jail"
        / "Data"
        / "tmp"
        / "ej_matrix_out"
    )
    out_dir = out_root / "baseline"
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)
    cmd = [str(EJ), "run-matrix", "--group", "baseline", "--out", str(out_dir), "capabilities_snapshot"]
    res = run_cmd(cmd)
    dest_dir = MATRIX_DIR / "out_baseline"
    copy_error = _copy_tree(out_dir, dest_dir)
    report_path = dest_dir / "run-matrix.json"
    report_json = None
    output_dir = None
    if report_path.exists():
        report_json = maybe_parse_json(report_path.read_text())
        if isinstance(report_json, dict):
            output_dir = report_json.get("data", {}).get("output_dir")
    runs.append(
        {
            "out_dir": str(out_dir),
            "dest_dir": str(dest_dir.relative_to(REPO_ROOT)),
            "copy_error": copy_error,
            "report_output_dir": output_dir,
            "report_path": str(report_path.relative_to(REPO_ROOT)),
            "report_parsed": report_json is not None,
            **res,
        }
    )

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "run_matrix_out",
        "runs": runs,
    }
    return {"run_matrix_out": payload}


def scenario_bundle_evidence_out(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    runs: List[Dict[str, object]] = []
    out_dir = (
        Path.home()
        / "Library"
        / "Containers"
        / "com.yourteam.entitlement-jail"
        / "Data"
        / "tmp"
        / "ej_evidence_out"
    )
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)
    cmd = [str(EJ), "bundle-evidence", "--out", str(out_dir), "--include-health-check"]
    if ack_risk:
        cmd += ["--ack-risk", ack_risk]
    res = run_cmd(cmd)
    dest_dir = OUT_ROOT / "evidence_out"
    copy_error = _copy_tree(out_dir, dest_dir)
    stdout_json = maybe_parse_json(res.get("stdout", "").strip())
    output_dir = None
    if isinstance(stdout_json, dict):
        output_dir = stdout_json.get("data", {}).get("output_dir")
    runs.append(
        {
            "out_dir": str(out_dir),
            "dest_dir": str(dest_dir.relative_to(REPO_ROOT)),
            "copy_error": copy_error,
            "stdout_json": stdout_json,
            "report_output_dir": output_dir,
            **res,
        }
    )

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "bundle_evidence_out",
        "runs": runs,
    }
    return {"bundle_evidence_out": payload}


def scenario_quarantine_lab(*, ack_risk: Optional[str]) -> Dict[str, Dict[str, object]]:
    runs: List[Dict[str, object]] = []
    show = run_cmd([str(EJ), "show-profile", "quarantine_default"])
    show_json = maybe_parse_json(show.get("stdout", "").strip())
    bundle_id = extract_profile_bundle_id(show_json)
    runs.append(
        {
            "command": show.get("command"),
            "exit_code": show.get("exit_code"),
            "stdout_json": show_json,
            "bundle_id": bundle_id,
            "error": show.get("error"),
        }
    )
    if bundle_id:
        cmd = [
            str(EJ),
            "quarantine-lab",
            bundle_id,
            "text",
            "--operation",
            "create_new",
            "--dir",
            "tmp",
            "--name",
            "ej_quarantine.txt",
            "--no-exec",
        ]
        res = run_cmd(cmd)
        res_json = maybe_parse_json(res.get("stdout", "").strip())
        runs.append(
            {
                "command": res.get("command"),
                "exit_code": res.get("exit_code"),
                "stdout_json": res_json,
                "error": res.get("error"),
                "stderr": res.get("stderr"),
            }
        )

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "quarantine_lab",
        "runs": runs,
    }
    return {"quarantine_lab": payload}
