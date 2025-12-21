"""
Run EntitlementJail run-xpc probes for entitlement-diff scenarios.

Each scenario writes a witness JSON plus per-run log captures under out/.
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from book.api import path_utils
from book.api.profile_tools.identity import baseline_world_id


REPO_ROOT = path_utils.find_repo_root(Path(__file__))
WORLD_ID = baseline_world_id(REPO_ROOT)
EJ_REL = Path("book/tools/entitlement/EntitlementJail.app/Contents/MacOS/entitlement-jail")
OUT_DIR = REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "out"
LOG_DIR = OUT_DIR / "jail_xpc_logs"

@dataclass(frozen=True)
class ServiceSpec:
    label: str
    service_id: str
    process_name: str


SERVICES = {
    "minimal": ServiceSpec(
        label="minimal",
        service_id="com.yourteam.entitlement-jail.ProbeService_minimal",
        process_name="ProbeService_minimal",
    ),
    "bookmarks_app_scope": ServiceSpec(
        label="bookmarks_app_scope",
        service_id="com.yourteam.entitlement-jail.ProbeService_bookmarks_app_scope",
        process_name="ProbeService_bookmarks_app_scope",
    ),
    "downloads_rw": ServiceSpec(
        label="downloads_rw",
        service_id="com.yourteam.entitlement-jail.ProbeService_downloads_rw",
        process_name="ProbeService_downloads_rw",
    ),
    "net_client": ServiceSpec(
        label="net_client",
        service_id="com.yourteam.entitlement-jail.ProbeService_net_client",
        process_name="ProbeService_net_client",
    ),
}


def _safe_tag(tag: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in tag)


def _build_log_predicate(process_names: Sequence[str]) -> str:
    fragments = " OR ".join(f'eventMessage CONTAINS[c] "{name}"' for name in process_names)
    return f'(process == "kernel" AND eventMessage CONTAINS[c] "Sandbox:" AND ({fragments}))'


def _run_with_log_capture(
    *,
    log_path: Path,
    predicate: str,
    pre_s: float,
    post_s: float,
    action: Callable[[], subprocess.CompletedProcess[str]],
) -> tuple[subprocess.CompletedProcess[str], Dict[str, object]]:
    log_cmd = ["/usr/bin/log", "stream", "--style", "compact", "--predicate", predicate, "--info", "--debug"]
    log_meta: Dict[str, object] = {
        "command": path_utils.relativize_command(log_cmd, REPO_ROOT),
        "path": path_utils.to_repo_relative(log_path, REPO_ROOT),
        "exit_code": None,
        "stderr": None,
        "error": None,
    }

    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log_path.open("w") as fh:
            proc = subprocess.Popen(log_cmd, stdout=fh, stderr=subprocess.PIPE, text=True)
            time.sleep(pre_s)
            result = action()
            time.sleep(post_s)
            proc.terminate()
            try:
                _, stderr_text = proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, stderr_text = proc.communicate(timeout=2)
            log_meta["stderr"] = stderr_text
            log_meta["exit_code"] = proc.returncode
            return result, log_meta
    except Exception as exc:
        log_meta["error"] = f"{type(exc).__name__}: {exc}"
        return action(), log_meta


def run_xpc(
    *,
    scenario: str,
    service: ServiceSpec,
    probe_id: str,
    probe_args: List[str],
    log_tag: str,
    log_predicate: str,
    pre_s: float,
    post_s: float,
) -> Dict[str, object]:
    cmd = [str(EJ_REL), "run-xpc", service.service_id, probe_id, *probe_args]

    def _action() -> subprocess.CompletedProcess[str]:
        return subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))

    log_path = LOG_DIR / f"{_safe_tag(log_tag)}.log"
    res, log_meta = _run_with_log_capture(
        log_path=log_path,
        predicate=log_predicate,
        pre_s=pre_s,
        post_s=post_s,
        action=_action,
    )

    record: Dict[str, object] = {
        "scenario": scenario,
        "service_label": service.label,
        "service_id": service.service_id,
        "probe_id": probe_id,
        "probe_args": probe_args,
        "command": path_utils.relativize_command(cmd, REPO_ROOT),
        "exit_code": res.returncode,
        "stdout": res.stdout,
        "stderr": res.stderr,
        "log_capture": log_meta,
        "log_predicate": log_predicate,
    }
    stdout = res.stdout.strip()
    if stdout:
        try:
            record["stdout_json"] = json.loads(stdout)
        except Exception as exc:
            record["stdout_json_error"] = f"{type(exc).__name__}: {exc}"
    return record


def _service_path(service_id: str, suffix: str) -> str:
    return str(Path.home() / "Library" / "Containers" / service_id / "Data" / "tmp" / suffix)


def _run_tcp_listener(host: str = "127.0.0.1", timeout_s: float = 2.0) -> tuple[Dict[str, object], Callable[[], Dict[str, object]]]:
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


def run_bookmarks(pre_s: float, post_s: float) -> Dict[str, object]:
    minimal = SERVICES["minimal"]
    bookmarks = SERVICES["bookmarks_app_scope"]
    bookmark_filename = "ej_bookmark_target.txt"
    runs: List[Dict[str, object]] = []
    extra_names = ["ScopedBookmarkAgent"]

    for service in [minimal, bookmarks]:
        log_predicate = _build_log_predicate([service.process_name, *extra_names])
        runs.append(
            run_xpc(
                scenario="bookmarks",
                service=service,
                probe_id="capabilities_snapshot",
                probe_args=[],
                log_tag=f"bookmarks.{service.label}.capabilities_snapshot",
                log_predicate=log_predicate,
                pre_s=pre_s,
                post_s=post_s,
            )
        )
        runs.append(
            run_xpc(
                scenario="bookmarks",
                service=service,
                probe_id="world_shape",
                probe_args=[],
                log_tag=f"bookmarks.{service.label}.world_shape",
                log_predicate=log_predicate,
                pre_s=pre_s,
                post_s=post_s,
            )
        )

    for service in [minimal, bookmarks]:
        target_path = _service_path(service.service_id, bookmark_filename)
        log_predicate = _build_log_predicate([service.process_name, *extra_names])
        runs.append(
            run_xpc(
                scenario="bookmarks",
                service=service,
                probe_id="fs_op",
                probe_args=["--op", "create", "--path", target_path, "--allow-unsafe-path"],
                log_tag=f"bookmarks.{service.label}.fs_create",
                log_predicate=log_predicate,
                pre_s=pre_s,
                post_s=post_s,
            )
        )
        runs.append(
            run_xpc(
                scenario="bookmarks",
                service=service,
                probe_id="bookmark_make",
                probe_args=["--path", target_path],
                log_tag=f"bookmarks.{service.label}.bookmark_make",
                log_predicate=log_predicate,
                pre_s=pre_s,
                post_s=post_s,
            )
        )

    bookmark_b64: Optional[str] = None
    for record in runs:
        if record.get("service_label") != bookmarks.label or record.get("probe_id") != "bookmark_make":
            continue
        stdout_json = record.get("stdout_json")
        if isinstance(stdout_json, dict):
            bookmark_b64 = stdout_json.get("stdout")
        break

    if bookmark_b64:
        runs.append(
            run_xpc(
                scenario="bookmarks",
                service=bookmarks,
                probe_id="bookmark_op",
                probe_args=["--bookmark-b64", bookmark_b64, "--op", "stat"],
                log_tag="bookmarks.bookmarks_app_scope.bookmark_op_stat",
                log_predicate=_build_log_predicate([bookmarks.process_name, *extra_names]),
                pre_s=pre_s,
                post_s=post_s,
            )
        )

    return {
        "scenario": "bookmarks",
        "services": {
            "minimal": minimal.service_id,
            "bookmarks_app_scope": bookmarks.service_id,
        },
        "runs": runs,
    }


def run_downloads(pre_s: float, post_s: float) -> Dict[str, object]:
    minimal = SERVICES["minimal"]
    downloads = SERVICES["downloads_rw"]
    runs: List[Dict[str, object]] = []

    for service in [minimal, downloads]:
        log_predicate = _build_log_predicate([service.process_name])
        runs.append(
            run_xpc(
                scenario="downloads_rw",
                service=service,
                probe_id="capabilities_snapshot",
                probe_args=[],
                log_tag=f"downloads.{service.label}.capabilities_snapshot",
                log_predicate=log_predicate,
                pre_s=pre_s,
                post_s=post_s,
            )
        )
        runs.append(
            run_xpc(
                scenario="downloads_rw",
                service=service,
                probe_id="world_shape",
                probe_args=[],
                log_tag=f"downloads.{service.label}.world_shape",
                log_predicate=log_predicate,
                pre_s=pre_s,
                post_s=post_s,
            )
        )
        runs.append(
            run_xpc(
                scenario="downloads_rw",
                service=service,
                probe_id="downloads_rw",
                probe_args=[],
                log_tag=f"downloads.{service.label}.downloads_rw",
                log_predicate=log_predicate,
                pre_s=pre_s,
                post_s=post_s,
            )
        )

    return {
        "scenario": "downloads_rw",
        "services": {
            "minimal": minimal.service_id,
            "downloads_rw": downloads.service_id,
        },
        "runs": runs,
    }


def run_net_client(pre_s: float, post_s: float) -> Dict[str, object]:
    minimal = SERVICES["minimal"]
    net_client = SERVICES["net_client"]
    runs: List[Dict[str, object]] = []
    host = "127.0.0.1"

    for service in [minimal, net_client]:
        log_predicate = _build_log_predicate([service.process_name])
        runs.append(
            run_xpc(
                scenario="net_client",
                service=service,
                probe_id="capabilities_snapshot",
                probe_args=[],
                log_tag=f"net_client.{service.label}.capabilities_snapshot",
                log_predicate=log_predicate,
                pre_s=pre_s,
                post_s=post_s,
            )
        )
        runs.append(
            run_xpc(
                scenario="net_client",
                service=service,
                probe_id="world_shape",
                probe_args=[],
                log_tag=f"net_client.{service.label}.world_shape",
                log_predicate=log_predicate,
                pre_s=pre_s,
                post_s=post_s,
            )
        )

        listener_state, finish_listener = _run_tcp_listener(host=host, timeout_s=2.0)
        net_args = ["--op", "tcp_connect", "--host", host, "--port", str(listener_state["port"])]
        record = run_xpc(
            scenario="net_client",
            service=service,
            probe_id="net_op",
            probe_args=net_args,
            log_tag=f"net_client.{service.label}.tcp_connect",
            log_predicate=log_predicate,
            pre_s=pre_s,
            post_s=post_s,
        )
        record["listener"] = finish_listener()
        runs.append(record)

    return {
        "scenario": "net_client",
        "services": {
            "minimal": minimal.service_id,
            "net_client": net_client.service_id,
        },
        "runs": runs,
        "net_op": {"op": "tcp_connect", "host": host, "port": "dynamic"},
    }


def write_json(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"[+] wrote {path_utils.to_repo_relative(path, REPO_ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run EntitlementJail run-xpc probes for entitlement-diff.")
    parser.add_argument(
        "--scenario",
        default="all",
        choices=["bookmarks", "downloads_rw", "net_client", "all"],
        help="Scenario to run (default: all).",
    )
    parser.add_argument("--pre-s", type=float, default=0.2, help="Seconds to wait before running command.")
    parser.add_argument("--post-s", type=float, default=0.5, help="Seconds to wait after command completes.")
    args = parser.parse_args()

    payloads: Dict[str, Dict[str, object]] = {}
    if args.scenario in {"bookmarks", "all"}:
        payloads["bookmarks"] = run_bookmarks(args.pre_s, args.post_s)
    if args.scenario in {"downloads_rw", "all"}:
        payloads["downloads_rw"] = run_downloads(args.pre_s, args.post_s)
    if args.scenario in {"net_client", "all"}:
        payloads["net_client"] = run_net_client(args.pre_s, args.post_s)

    for scenario, payload in payloads.items():
        payload.update(
            {
                "world_id": WORLD_ID,
                "entrypoint": path_utils.to_repo_relative(EJ_REL, REPO_ROOT),
            "log_capture": {"pre_s": args.pre_s, "post_s": args.post_s},
        }
    )
        out_path = OUT_DIR / f"jail_xpc_{scenario}_witness.json"
        write_json(out_path, payload)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
