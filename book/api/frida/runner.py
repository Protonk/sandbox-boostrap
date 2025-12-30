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


def _sanitize_text(text: str) -> str:
    msg = " ".join(str(text).split())
    return re.sub(r"0x[0-9a-fA-F]+", "0x<addr>", msg)


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
    outcome: dict[str, object] = {"status": "running", "reason": None, "error": None, "details": None}

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
        "tooling": {
            "python": {
                "version": platform.python_version(),
                "implementation": platform.python_implementation(),
            },
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "mac_ver": platform.mac_ver()[0],
            },
            "frida": {
                "python_pkg_version": None,
            },
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
        "outcome": outcome,
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

    abort_reason: dict[str, object] = {"kind": None, "error": None}
    detach_info: dict[str, object] | None = None
    requested_detach = False

    def emit_runner(kind: str, **fields) -> None:
        writer.emit_runner({"kind": kind, **fields})

    def set_outcome_error(reason: str, *, error: str | None, details: dict[str, object] | None = None) -> None:
        outcome["status"] = "error"
        outcome["reason"] = reason
        outcome["error"] = error
        outcome["details"] = details

    def set_outcome_ok() -> None:
        outcome["status"] = "ok"
        outcome["reason"] = "clean"
        outcome["error"] = None
        outcome["details"] = None

    def request_abort(kind: str, *, error: str | None) -> None:
        abort_reason["kind"] = kind
        abort_reason["error"] = error

    emit_runner("runner-start")

    stage = "init"
    try:
        if not manifest_snapshot.get("ok"):
            emit_runner(
                "manifest-error",
                error=manifest_snapshot.get("manifest_error"),
                violations=manifest_snapshot.get("violations"),
                manifest_path=manifest_snapshot.get("manifest_path"),
            )
            set_outcome_error("manifest-error", error="manifest snapshot not ok")
            return 1

        emit_runner("config-validation", status=cfg_validation.get("status"), error=cfg_validation.get("error"))
        if cfg_validation.get("status") != "pass":
            emit_runner("config-error", error=cfg_validation.get("error"), violations=cfg_validation.get("violations"))
            meta["script"]["configure"] = {
                "status": "skipped",
                "present": None,
                "result": None,
                "error": cfg_validation.get("error"),
            }
            set_outcome_error("config-error", error=str(cfg_validation.get("error")))
            return 1

        try:
            import frida  # type: ignore

            meta["frida"]["python_pkg_version"] = getattr(frida, "__version__", None)
            meta["tooling"]["frida"]["python_pkg_version"] = getattr(frida, "__version__", None)
        except Exception as exc:
            err = _stable_error_string(exc)
            emit_runner("frida-import-error", error=err)
            meta["script"]["configure"] = {"status": "skipped", "present": None, "result": None, "error": err}
            set_outcome_error("frida-import-error", error=err)
            return 1

        stage = "device"
        emit_runner("stage", stage=stage)
        try:
            device = frida.get_local_device()
        except Exception as exc:
            err = _stable_error_string(exc)
            emit_runner("device-error", stage=stage, error=err)
            set_outcome_error("device-error", error=err, details={"stage": stage})
            return 1

        stage = "attach"
        emit_runner("stage", stage=stage)
        try:
            if spawn_argv:
                pid = device.spawn(spawn_argv)
                writer.set_pid(pid)
                session = device.attach(pid)
            else:
                pid = attach_pid
                writer.set_pid(pid)
                session = device.attach(pid)
        except Exception as exc:
            err = _stable_error_string(exc)
            emit_runner("attach-error", stage=stage, error=err)
            set_outcome_error("attach-error", error=err, details={"stage": stage})
            return 1

        def on_detached(reason, crash=None):
            nonlocal detach_info
            payload: dict[str, object] = {"reason": str(reason), "requested": bool(requested_detach)}
            if crash:
                payload["crash"] = crash
            detach_info = dict(payload)
            emit_runner("session-detached", **payload)
            if not requested_detach:
                request_abort("session-detached", error=str(reason))

        session.on("detached", on_detached)

        def on_message(msg, data):
            if not isinstance(msg, dict):
                emit_runner("agent-message-nonobject", msg_type=str(type(msg)))
                return

            writer.emit_agent_message(msg)
            if msg.get("type") == "error":
                desc = msg.get("description")
                stack = msg.get("stack")
                stable = _stable_error_string(Exception(str(desc) if desc is not None else "script error"))
                emit_runner(
                    "agent-error",
                    error=stable,
                    description=_sanitize_text(desc) if isinstance(desc, str) else None,
                    stack=_sanitize_text(stack) if isinstance(stack, str) else None,
                )
                request_abort("agent-error", error=stable)

        stage = "script-create"
        emit_runner("stage", stage=stage)
        try:
            script_obj = session.create_script(assembled_src.decode("utf-8"))
        except Exception as exc:
            err = _stable_error_string(exc)
            emit_runner("script-create-error", stage=stage, error=err)
            set_outcome_error("script-create-error", error=err, details={"stage": stage})
            return 1

        stage = "script-load"
        emit_runner("stage", stage=stage)
        script_obj.on("message", on_message)
        try:
            script_obj.load()
        except Exception as exc:
            err = _stable_error_string(exc)
            emit_runner("script-load-error", stage=stage, error=err)
            set_outcome_error("script-load-error", error=err, details={"stage": stage})
            return 1

        # Configure contract v1: call configure() once, immediately after script.load().
        stage = "configure"
        expected = expected_configure_present
        try:
            result = script_obj.exports_sync.configure(cfg_obj)
        except Exception as exc:
            if _looks_like_missing_export(exc, export_name="configure"):
                if expected is True:
                    err = "ConfigureMissingError: configure export absent"
                    meta["script"]["configure"] = {"status": "fail", "present": False, "result": None, "error": err}
                    emit_runner("configure", status="fail", present=False)
                    emit_runner("configure-error", error=err)
                    set_outcome_error("configure-error", error=err, details={"stage": stage})
                    return 1
                meta["script"]["configure"] = {"status": "absent", "present": False, "result": None, "error": None}
                emit_runner("configure", status="absent", present=False)
            else:
                err = _stable_error_string(exc)
                meta["script"]["configure"] = {"status": "fail", "present": True, "result": None, "error": err}
                emit_runner("configure", status="fail", present=True)
                emit_runner("configure-error", error=err)
                set_outcome_error("configure-error", error=err, details={"stage": stage})
                return 1
        else:
            if expected is False:
                err = "ConfigureMismatchError: manifest rpc.configure.present=false but configure export exists"
                meta["script"]["configure"] = {"status": "fail", "present": True, "result": None, "error": err}
                emit_runner("configure", status="fail", present=True)
                emit_runner("configure-error", error=err)
                set_outcome_error("configure-error", error=err, details={"stage": stage})
                return 1
            if not isinstance(result, dict):
                err = f"ConfigureTypeError: expected object return, got {_type_name(result)}"
                meta["script"]["configure"] = {"status": "fail", "present": True, "result": None, "error": err}
                emit_runner("configure", status="fail", present=True)
                emit_runner("configure-error", error=err)
                set_outcome_error("configure-error", error=err, details={"stage": stage})
                return 1
            meta["script"]["configure"] = {"status": "pass", "present": True, "result": result, "error": None}
            emit_runner("configure", status="pass", present=True)

        # Run loop: abort early on agent errors or unexpected detach.
        if spawn_argv:
            stage = "resume"
            emit_runner("stage", stage=stage)
            try:
                device.resume(pid)
            except Exception as exc:
                err = _stable_error_string(exc)
                emit_runner("resume-error", stage=stage, error=err)
                set_outcome_error("resume-error", error=err, details={"stage": stage})
                return 1
            run_duration = duration_s if duration_s is not None else 5.0
            deadline = time.monotonic() + max(run_duration, 0.0)
            while time.monotonic() < deadline:
                if abort_reason.get("kind") is not None:
                    break
                time.sleep(0.05)
            requested_detach = True
            try:
                session.detach()
            except Exception as exc:
                emit_runner("detach-error", stage=stage, error=_stable_error_string(exc))
        else:
            if duration_s is not None:
                stage = "attach-sleep"
                emit_runner("stage", stage=stage)
                deadline = time.monotonic() + max(duration_s, 0.0)
                while time.monotonic() < deadline:
                    if abort_reason.get("kind") is not None:
                        break
                    time.sleep(0.05)
                requested_detach = True
                try:
                    session.detach()
                except Exception as exc:
                    emit_runner("detach-error", stage=stage, error=_stable_error_string(exc))
            else:
                stage = "attach-loop"
                emit_runner("stage", stage=stage)
                try:
                    while True:
                        if abort_reason.get("kind") is not None:
                            break
                        time.sleep(0.25)
                except KeyboardInterrupt:
                    pass
                requested_detach = True
                try:
                    session.detach()
                except Exception as exc:
                    emit_runner("detach-error", stage=stage, error=_stable_error_string(exc))

        if abort_reason.get("kind") == "agent-error":
            set_outcome_error(
                "agent-error",
                error=str(abort_reason.get("error")),
                details={"stage": stage},
            )
            return 1
        if abort_reason.get("kind") == "session-detached":
            set_outcome_error(
                "session-detached",
                error=str(abort_reason.get("error")),
                details={"stage": stage, "detach": detach_info},
            )
            return 1

        set_outcome_ok()
        return 0
    except Exception as exc:
        err = _stable_error_string(exc)
        emit_runner("runner-exception", stage=stage, error=err)
        set_outcome_error("runner-exception", error=err, details={"stage": stage})
        return 1
    finally:
        emit_runner(
            "runner-end",
            status=outcome.get("status"),
            reason=outcome.get("reason"),
            error=outcome.get("error"),
            detach=detach_info,
        )
        try:
            if session is not None and not requested_detach:
                requested_detach = True
                session.detach()
        except Exception:
            pass
        (out_root / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True))
        jsonl.close()
