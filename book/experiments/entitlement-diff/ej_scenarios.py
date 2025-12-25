"""Scenario runners for EntitlementJail 1.x (entitlement-diff experiment)."""

from __future__ import annotations

import socket
import threading
import os
import shutil
import stat
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from ej_cli import (
    EJ,
    REPO_ROOT,
    WORLD_ID,
    bundle_evidence,
    copy_tree,
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
from ej_profiles import MATRIX_GROUPS, PROFILES
from ej_wait import run_probe_wait, run_wait_xpc

OUT_ROOT = REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "out" / "ej"
LOG_DIR = OUT_ROOT / "logs"
MATRIX_DIR = OUT_ROOT / "matrix"
EVIDENCE_DIR = OUT_ROOT / "evidence" / "latest"

PLAN_ID = "entitlement-diff:ej"


def _log_path(prefix: str, profile_label: str, probe_id: str) -> Path:
    return LOG_DIR / f"{prefix}.{profile_label}.{probe_id}.log"


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
    probe_ids = parse_probe_catalog(stdout_json)
    return bool(probe_ids and probe_id in probe_ids)


def _capture_tmp_dir(
    profile: object,
    *,
    tag: str,
    ack_risk: Optional[str],
    runs: List[Dict[str, object]],
) -> Optional[str]:
    snapshot = run_xpc(
        profile_id=profile.profile_id,
        service_id=profile.service_id,
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
                service_id=profile.service_id,
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
                    service_id=profile.service_id,
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
                    service_id=profile.service_id,
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
                    service_id=PROFILES["bookmarks_app_scope"].service_id,
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
                    service_id=profile.service_id,
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
                service_id=profile.service_id,
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
                    service_id=profile.service_id,
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
            service_id=profile.service_id,
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


def _run_userdefaults(profile, *, ack_risk: Optional[str]) -> List[Dict[str, object]]:
    runs = []
    for op in ["write", "read", "remove"]:
        args: List[str] = ["--op", op, "--key", "ej_ud_key"]
        if op == "write":
            args += ["--value", "1"]
        runs.append(
            run_xpc(
                profile_id=profile.profile_id,
                service_id=profile.service_id,
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
        service_id=profile.service_id,
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
        service_id=profile.service_id,
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
                service_id=profile.service_id,
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
                service_id=profile.service_id,
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
            service_id=profile.service_id,
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
            service_id=profile.service_id,
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
                    service_id=profile.service_id,
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
                    service_id=profile.service_id,
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
        service_id=profile.service_id,
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
            service_id=profile.service_id,
            probe_id="probe_catalog",
            probe_args=[],
            wait_args=["--attach", "5"],
            log_path=_log_path("wait_attach", profile.label, "attach_fifo"),
            plan_id=PLAN_ID,
            row_id="wait_attach.minimal.attach_fifo",
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
                "service_id": profile.service_id,
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
                    service_id=profile.service_id,
                    probe_id="fs_op",
                    probe_args=["--op", "stat", "--path-class", "tmp"],
                    wait_args=["--wait-fifo", str(fifo_path), "--wait-timeout-ms", "15000"],
                    log_path=_log_path("wait_attach", profile.label, "wait_fifo"),
                    plan_id=PLAN_ID,
                    row_id="wait_attach.minimal.wait_fifo",
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
                "service_id": profile.service_id,
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
                    service_id=profile.service_id,
                    probe_id="fs_op",
                    probe_args=["--op", "stat", "--path-class", "tmp"],
                    wait_args=["--wait-exists", str(trigger_path), "--wait-timeout-ms", "15000"],
                    log_path=_log_path("wait_attach", profile.label, "wait_exists"),
                    plan_id=PLAN_ID,
                    row_id="wait_attach.minimal.wait_exists",
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
                service_id=profile.service_id,
                probe_id="probe_catalog",
                probe_args=[],
                wait_args=[
                    "--wait-exists",
                    str(wait_path),
                    "--wait-timeout-ms",
                    str(case["wait_timeout_ms"]),
                ],
                log_path=_log_path("wait_timeout", profile.label, case["case_id"]),
                plan_id=PLAN_ID,
                row_id=f"wait_timeout.{profile.label}.{case['case_id']}",
                trigger_delay_s=case["trigger_delay_s"],
                wait_ready_timeout_s=10.0,
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

    wait_args = [
        "--wait-path-class",
        "tmp",
        "--wait-name",
        "ej_wait_path_class",
        "--wait-timeout-ms",
        "10000",
    ]

    runs.append(
        run_wait_xpc(
            profile_id=profile.profile_id,
            service_id=profile.service_id,
            probe_id="probe_catalog",
            probe_args=[],
            wait_args=wait_args,
            log_path=_log_path("wait_path_class", profile.label, "path_class"),
            plan_id=PLAN_ID,
            row_id="wait_path_class.minimal.path_class",
            trigger_delay_s=0.1,
            wait_ready_timeout_s=10.0,
        )
    )

    payload = {
        "world_id": WORLD_ID,
        "entrypoint": str(EJ.relative_to(REPO_ROOT)),
        "scenario": "wait_path_class",
        "tmp_dir": tmp_dir,
        "wait_args": wait_args,
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
                "service_id": profile.service_id,
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
                    service_id=profile.service_id,
                    probe_id="probe_catalog",
                    probe_args=[],
                    wait_args=["--wait-fifo", str(fifo_path), "--wait-timeout-ms", "15000"],
                    log_path=_log_path("wait_multi", profile.label, "fifo"),
                    plan_id=PLAN_ID,
                    row_id="wait_multi.minimal.fifo",
                    trigger_delay_s=0.05,
                    post_trigger=True,
                    post_trigger_delay_s=0.2,
                    wait_ready_timeout_s=10.0,
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
                "service_id": profile.service_id,
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
                    service_id=profile.service_id,
                    probe_id="probe_catalog",
                    probe_args=[],
                    wait_args=["--wait-exists", str(exists_path), "--wait-timeout-ms", "15000"],
                    log_path=_log_path("wait_multi", profile.label, "exists"),
                    plan_id=PLAN_ID,
                    row_id="wait_multi.minimal.exists",
                    trigger_delay_s=0.05,
                    post_trigger=True,
                    post_trigger_delay_s=0.2,
                    wait_ready_timeout_s=10.0,
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
                "service_id": profile.service_id,
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
                    service_id=profile.service_id,
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
                "service_id": profile.service_id,
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
                    service_id=profile.service_id,
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
            service_id=profile.service_id,
            probe_id="probe_catalog",
            probe_args=[],
            wait_args=["--attach", "5", "--hold-open", "3"],
            log_path=_log_path("wait_hold_open", profile.label, "attach_hold"),
            plan_id=PLAN_ID,
            row_id="wait_hold_open.minimal.attach_hold",
            trigger_delay_s=0.05,
            wait_ready_timeout_s=10.0,
            process_timeout_s=20.0,
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
                "service_id": profile.service_id,
                "probe_id": "wait_create_prep",
                "row_id": "wait_create.minimal.prep",
                "fifo_path": str(fifo_path) if fifo_path else None,
                "prep_error": prep_error or "missing_tmp_dir",
            }
        )
    else:
        record = run_wait_xpc(
            profile_id=profile.profile_id,
            service_id=profile.service_id,
            probe_id="probe_catalog",
            probe_args=[],
            wait_args=["--wait-fifo", str(fifo_path), "--wait-create", "--wait-timeout-ms", "15000"],
            log_path=_log_path("wait_create", profile.label, "wait_create"),
            plan_id=PLAN_ID,
            row_id="wait_create.minimal.wait_create",
            trigger_delay_s=0.1,
            wait_ready_timeout_s=10.0,
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
                service_id=profile.service_id,
                probe_id="probe_catalog",
                probe_args=[],
                wait_args=[
                    "--wait-exists",
                    str(wait_path),
                    "--wait-timeout-ms",
                    "2000",
                    "--wait-interval-ms",
                    str(case["interval_ms"]),
                ],
                log_path=_log_path("wait_interval", profile.label, case["case_id"]),
                plan_id=PLAN_ID,
                row_id=f"wait_interval.{profile.label}.{case['case_id']}",
                trigger_delay_s=0.1,
                wait_ready_timeout_s=10.0,
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
            service_id=profile.service_id,
            probe_id="probe_catalog",
            probe_args=[],
            wait_args=["--attach", "3"],
            log_path=_log_path("attach_default", profile.label, "attach_default"),
            plan_id=PLAN_ID,
            row_id="attach_default.minimal.attach_default",
            trigger_delay_s=0.1,
            wait_ready_timeout_s=10.0,
            process_timeout_s=15.0,
        )
    )
    runs.append(
        run_wait_xpc(
            profile_id=profile.profile_id,
            service_id=profile.service_id,
            probe_id="probe_catalog",
            probe_args=[],
            wait_args=["--attach", "3", "--hold-open", "0"],
            log_path=_log_path("attach_default", profile.label, "attach_hold_open_zero"),
            plan_id=PLAN_ID,
            row_id="attach_default.minimal.attach_hold_open_zero",
            trigger_delay_s=0.1,
            wait_ready_timeout_s=10.0,
            process_timeout_s=15.0,
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
    copy_error = copy_tree(out_dir, dest_dir)
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
    copy_error = copy_tree(out_dir, dest_dir)
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
