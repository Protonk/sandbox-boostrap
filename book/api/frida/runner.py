#!/usr/bin/env python3
import hashlib
import json
import platform
import re
import subprocess
import time
import uuid
from pathlib import Path

from book.api import path_utils
from book.api.frida.config import load_and_validate_config
from book.api.frida.hook_manifest import load_manifest_snapshot
from book.api.frida.script_assembly import assemble_script_source
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


def _stable_error_string(exc: Exception) -> str:
    msg = " ".join(str(exc).split())
    msg = re.sub(r"0x[0-9a-fA-F]+", "0x<addr>", msg)
    return f"{type(exc).__name__}: {msg}"


def _type_name(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _looks_like_missing_export(exc: Exception, *, export_name: str) -> bool:
    msg = str(exc).lower()
    name = export_name.lower()
    if name not in msg:
        return False
    if "export" in msg and ("no" in msg or "missing" in msg or "not" in msg):
        return True
    if "has no attribute" in msg:
        return True
    return False


def run(
    *,
    spawn: list[str] | None,
    attach_pid: int | None,
    script: str,
    config_json: str | None = None,
    config_path: str | None = None,
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
    assembled_src, assembly_meta = assemble_script_source(script_path=js_path_abs, repo_root=repo_root)
    manifest_snapshot = load_manifest_snapshot(script_path=js_path_abs, repo_root=repo_root)

    spawn_exec_abs: Path | None = None
    spawn_argv: list[str] | None = None
    if spawn:
        spawn_exec_abs = path_utils.ensure_absolute(spawn[0], repo_root)
        if not spawn_exec_abs.exists():
            raise SystemExit(f"spawn target not found: {spawn_exec_abs}")
        spawn_argv = [str(spawn_exec_abs)] + list(spawn[1:])

    manifest = manifest_snapshot.get("manifest") if manifest_snapshot.get("ok") else None
    config_schema = None
    expected_configure_present: bool | None = None
    if isinstance(manifest, dict):
        config_obj = manifest.get("config")
        if isinstance(config_obj, dict):
            config_schema = config_obj.get("schema")
        rpc = manifest.get("rpc")
        if isinstance(rpc, dict):
            cfg = rpc.get("configure")
            if isinstance(cfg, dict) and isinstance(cfg.get("present"), bool):
                expected_configure_present = bool(cfg.get("present"))

    cfg_obj, cfg_snapshot, cfg_validation = load_and_validate_config(
        config_json=config_json,
        config_path=config_path,
        config_obj=None,
        config_source=None,
        config_schema=config_schema,  # type: ignore[arg-type]
        repo_root=repo_root,
    )

    configure_record: dict[str, object] = {"status": "skipped", "present": None, "result": None, "error": None}

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
            "python_pkg_version": None,
        },
        "script": {
            "path": path_utils.to_repo_relative(js_path_abs, repo_root),
            "resolved_path": path_utils.to_repo_relative(js_path_resolved, repo_root),
            "sha256": sha256_bytes(js_src),
            "assembled_sha256": assembly_meta.get("assembled_sha256"),
            "assembly_version": assembly_meta.get("assembly_version"),
            "helper": assembly_meta.get("helper"),
            "manifest": manifest_snapshot.get("manifest"),
            "manifest_path": manifest_snapshot.get("manifest_path"),
            "manifest_sha256": manifest_snapshot.get("manifest_sha256"),
            "manifest_error": manifest_snapshot.get("manifest_error"),
            "manifest_violations": manifest_snapshot.get("violations"),
            "config": cfg_snapshot,
            "config_validation": cfg_validation,
            "configure": configure_record,
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

    jsonl = (out_root / "events.jsonl").open("w", encoding="utf-8")

    pid: int | None = attach_pid if attach_pid is not None else None
    session = None
    device = None

    writer = TraceWriterV1(jsonl, run_id=run_id, pid=pid)

    def emit_runner(kind: str, **fields) -> None:
        writer.emit_runner({"kind": kind, **fields})

    emit_runner("runner-start")

    if not manifest_snapshot.get("ok"):
        emit_runner(
            "manifest-error",
            error=manifest_snapshot.get("manifest_error"),
            violations=manifest_snapshot.get("violations"),
            manifest_path=manifest_snapshot.get("manifest_path"),
        )
        (out_root / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True))
        jsonl.close()
        return 1

    emit_runner("config-validation", status=cfg_validation.get("status"), error=cfg_validation.get("error"))
    if cfg_validation.get("status") != "pass":
        emit_runner("config-error", error=cfg_validation.get("error"), violations=cfg_validation.get("violations"))
        meta["script"]["configure"] = {"status": "skipped", "present": None, "result": None, "error": cfg_validation.get("error")}
        (out_root / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True))
        jsonl.close()
        return 1

    try:
        import frida  # type: ignore

        meta["frida"]["python_pkg_version"] = getattr(frida, "__version__", None)
    except Exception as exc:
        emit_runner("frida-import-error", error=_stable_error_string(exc))
        meta["script"]["configure"] = {"status": "skipped", "present": None, "result": None, "error": _stable_error_string(exc)}
        (out_root / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True))
        jsonl.close()
        return 1

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
        script_obj = session.create_script(assembled_src.decode("utf-8"))
        script_obj.on("message", on_message)
        script_obj.load()

        # Configure contract v1: call configure() once, immediately after script.load().
        expected = expected_configure_present
        actual_present = False
        try:
            result = script_obj.exports_sync.configure(cfg_obj)
        except Exception as exc:
            if _looks_like_missing_export(exc, export_name="configure"):
                actual_present = False
                if expected is True:
                    err = "ConfigureMissingError: configure export absent"
                    meta["script"]["configure"] = {"status": "fail", "present": False, "result": None, "error": err}
                    emit_runner("configure", status="fail", present=False)
                    emit_runner("configure-error", error=err)
                    return 1
                meta["script"]["configure"] = {"status": "absent", "present": False, "result": None, "error": None}
                emit_runner("configure", status="absent", present=False)
            else:
                actual_present = True
                err = _stable_error_string(exc)
                meta["script"]["configure"] = {"status": "fail", "present": True, "result": None, "error": err}
                emit_runner("configure", status="fail", present=True)
                emit_runner("configure-error", error=err)
                return 1
        else:
            actual_present = True
            if expected is False:
                err = "ConfigureMismatchError: manifest rpc.configure.present=false but configure export exists"
                meta["script"]["configure"] = {"status": "fail", "present": True, "result": None, "error": err}
                emit_runner("configure", status="fail", present=True)
                emit_runner("configure-error", error=err)
                return 1
            if not isinstance(result, dict):
                err = f"ConfigureTypeError: expected object return, got {_type_name(result)}"
                meta["script"]["configure"] = {"status": "fail", "present": True, "result": None, "error": err}
                emit_runner("configure", status="fail", present=True)
                emit_runner("configure-error", error=err)
                return 1
            meta["script"]["configure"] = {"status": "pass", "present": True, "result": result, "error": None}
            emit_runner("configure", status="pass", present=True)

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
        try:
            if session is not None:
                session.detach()
        except Exception:
            pass
        (out_root / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True))
        jsonl.close()

    return 0
