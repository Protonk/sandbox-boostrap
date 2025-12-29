#!/usr/bin/env python3
import hashlib
import json
import platform
import subprocess
import time
import uuid
from pathlib import Path

import frida

from book.api import path_utils
from book.api.frida.hook_manifest import load_manifest_snapshot
from book.api.frida.trace_writer import TraceWriterV1, now_ns
from book.api.profile.identity import baseline_world_id
from book.api.frida.trace_v1 import trace_event_schema_stamp


def sha256_bytes(blob: bytes) -> str:
    h = hashlib.sha256()
    h.update(blob)
    return h.hexdigest()


def try_cmd(*cmd: str) -> str | None:
    try:
        return subprocess.check_output(list(cmd), text=True).strip()
    except Exception:
        return None


def run(
    *,
    spawn: list[str] | None,
    attach_pid: int | None,
    script: str,
    out_dir: str = "book/api/frida/out",
    duration_s: float | None = None,
) -> int:
    if (spawn is None) == (attach_pid is None):
        raise SystemExit("Specify exactly one of --spawn or --attach-pid")

    repo_root = path_utils.find_repo_root()
    world_id = baseline_world_id(repo_root)

    run_id = str(uuid.uuid4())
    out_dir_abs = path_utils.ensure_absolute(out_dir, repo_root)
    out_root = out_dir_abs / run_id
    out_root.mkdir(parents=True, exist_ok=True)

    js_path_abs = path_utils.ensure_absolute(script, repo_root)
    js_src = js_path_abs.read_bytes()
    try:
        js_path_resolved = js_path_abs.resolve()
    except Exception:
        js_path_resolved = js_path_abs

    spawn_exec_abs: Path | None = None
    spawn_argv: list[str] | None = None
    if spawn:
        spawn_exec_abs = path_utils.ensure_absolute(spawn[0], repo_root)
        if not spawn_exec_abs.exists():
            raise SystemExit(f"spawn target not found: {spawn_exec_abs}")
        spawn_argv = [str(spawn_exec_abs)] + list(spawn[1:])

    meta = {
        "run_id": run_id,
        "world_id": world_id,
        "trace_event_schema": trace_event_schema_stamp(),
        "t0_ns": now_ns(),
        "out_dir": path_utils.to_repo_relative(out_root, repo_root),
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "sw_vers": {
                "productVersion": try_cmd("sw_vers", "-productVersion"),
                "buildVersion": try_cmd("sw_vers", "-buildVersion"),
            },
        },
        "frida": {
            "python_pkg_version": getattr(frida, "__version__", None),
        },
        "script": {
            "path": path_utils.to_repo_relative(js_path_abs, repo_root),
            "resolved_path": (
                path_utils.to_repo_relative(js_path_resolved, repo_root) if js_path_resolved != js_path_abs else None
            ),
            "sha256": sha256_bytes(js_src),
            "manifest": load_manifest_snapshot(script_path=js_path_abs, repo_root=repo_root),
        },
        "mode": "spawn" if spawn else "attach",
        "target": {
            "spawn_argv": (
                [path_utils.to_repo_relative(spawn_exec_abs, repo_root)] + list(spawn[1:])
                if spawn_exec_abs and spawn
                else None
            ),
            "attach_pid": attach_pid,
        },
    }
    (out_root / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True))

    jsonl = (out_root / "events.jsonl").open("w", encoding="utf-8")

    pid: int | None = attach_pid if attach_pid is not None else None
    session = None
    device = None

    writer = TraceWriterV1(jsonl, run_id=run_id, pid=pid)

    def emit_runner(kind: str, **fields) -> None:
        writer.emit_runner({"kind": kind, **fields})

    emit_runner("runner-start")

    stage = "device"
    try:
        emit_runner("stage", stage=stage)
        device = frida.get_local_device()

        stage = "attach"
        emit_runner("stage", stage=stage)
        if spawn_argv:
            pid = device.spawn(spawn_argv)
            writer.set_pid(pid)
            session = device.attach(pid)
        else:
            pid = attach_pid
            writer.set_pid(pid)
            session = device.attach(pid)

        def on_detached(reason, crash=None):
            payload = {"reason": str(reason)}
            if crash:
                payload["crash"] = crash
            emit_runner("session-detached", **payload)

        session.on("detached", on_detached)

        def on_message(msg, data):
            writer.emit_agent_message(msg)

        stage = "script-load"
        emit_runner("stage", stage=stage)
        script_obj = session.create_script(js_src.decode("utf-8"))
        script_obj.on("message", on_message)
        script_obj.load()

        if spawn_argv:
            stage = "resume"
            emit_runner("stage", stage=stage)
            device.resume(pid)
            run_duration = duration_s if duration_s is not None else 5.0
            time.sleep(run_duration)
            session.detach()
        else:
            if duration_s is not None:
                stage = "attach-sleep"
                emit_runner("stage", stage=stage)
                time.sleep(duration_s)
                session.detach()
            else:
                stage = "attach-loop"
                emit_runner("stage", stage=stage)
                try:
                    while True:
                        time.sleep(0.25)
                except KeyboardInterrupt:
                    session.detach()
    except Exception as exc:
        emit_runner("runner-exception", stage=stage, error=str(exc))
        raise
    finally:
        jsonl.close()

    return 0
