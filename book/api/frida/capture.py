"""Frida attach helper with JSONL event capture."""

from __future__ import annotations

import hashlib
import json
import platform
import re
from pathlib import Path
from typing import Any, Dict, Optional

from book.api import path_utils
from book.api.frida.config import load_and_validate_config
from book.api.frida.hook_manifest import load_manifest_snapshot
from book.api.frida.script_assembly import assemble_script_source
from book.api.frida.trace_v1 import trace_event_schema_stamp
from book.api.frida.trace_writer import TraceWriterV1, now_ns


def sha256_bytes(blob: bytes) -> str:
    h = hashlib.sha256()
    h.update(blob)
    return h.hexdigest()


def _stable_error_string(exc: Exception) -> str:
    msg = " ".join(str(exc).split())
    msg = re.sub(r"0x[0-9a-fA-F]+", "0x<addr>", msg)
    return f"{type(exc).__name__}: {msg}"


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


class FridaCapture:
    def __init__(
        self,
        *,
        run_id: str,
        pid: int,
        script_path: Path,
        events_path: Path,
        meta_path: Path,
        config_json: Optional[str],
        config_path: Optional[str],
        config_overlay: Optional[Dict[str, object]],
        config_overlay_source: Optional[Dict[str, object]],
        repo_root: Path,
    ) -> None:
        self.run_id = run_id
        self.pid = pid
        self.script_path = script_path
        self.events_path = events_path
        self.meta_path = meta_path
        self.config_json = config_json
        self.config_path = config_path
        self.config_overlay = dict(config_overlay) if isinstance(config_overlay, dict) else {}
        self.config_overlay_source = (
            dict(config_overlay_source) if isinstance(config_overlay_source, dict) else {"kind": "overlay"}
        )
        self.repo_root = repo_root
        self.events_fp = self.events_path.open("w", encoding="utf-8")
        self.writer = TraceWriterV1(self.events_fp, run_id=self.run_id, pid=self.pid)
        self.session = None
        self.script = None
        self.config_obj: Dict[str, object] = {}
        self.config_snapshot: Dict[str, object] = {"source": {"kind": "none"}, "value": {}}
        self.config_validation: Dict[str, object] = {"status": "pass", "error": None, "violations": []}
        self.configure_record: Dict[str, object] = {"status": "skipped", "present": None, "result": None, "error": None}
        self.js_src = self.script_path.read_bytes()
        try:
            self.script_path_resolved = self.script_path.resolve()
        except Exception:
            self.script_path_resolved = self.script_path
        self.assembled_src, self.assembly_meta = assemble_script_source(
            script_path=self.script_path, repo_root=self.repo_root
        )
        self.manifest_snapshot = load_manifest_snapshot(script_path=self.script_path, repo_root=self.repo_root)

    def _emit_runner(self, kind: str, **fields: object) -> None:
        payload: Dict[str, object] = {"kind": kind}
        payload.update(fields)
        self.writer.emit_runner(payload)

    def attach(self) -> Optional[str]:
        self._emit_runner("runner-start")
        if not self.manifest_snapshot.get("ok"):
            self._emit_runner(
                "manifest-error",
                error=self.manifest_snapshot.get("manifest_error"),
                violations=self.manifest_snapshot.get("violations"),
                manifest_path=self.manifest_snapshot.get("manifest_path"),
            )
            err = self.manifest_snapshot.get("manifest_error")
            if isinstance(err, dict):
                code = err.get("code") if isinstance(err.get("code"), str) else "unknown"
                msg = err.get("message") if isinstance(err.get("message"), str) else "manifest snapshot not ok"
            else:
                code = "unknown"
                msg = "manifest snapshot not ok"
            return f"ManifestError:{code}:{msg}"

        manifest = self.manifest_snapshot.get("manifest")
        config_schema = None
        expected_configure_present: bool | None = None
        if isinstance(manifest, dict):
            cfg = manifest.get("config")
            if isinstance(cfg, dict):
                config_schema = cfg.get("schema")
            rpc = manifest.get("rpc")
            if isinstance(rpc, dict):
                c = rpc.get("configure")
                if isinstance(c, dict) and isinstance(c.get("present"), bool):
                    expected_configure_present = bool(c.get("present"))

        if self.config_overlay:
            base_cfg, base_snapshot, base_validation = load_and_validate_config(
                config_json=self.config_json,
                config_path=self.config_path,
                config_obj=None,
                config_source=None,
                config_schema={"type": "object", "additionalProperties": True},
                repo_root=self.repo_root,
            )
            if base_validation.get("status") != "pass":
                self.config_obj = base_cfg
                self.config_snapshot = base_snapshot
                self.config_validation = base_validation
                self.configure_record = {
                    "status": "skipped",
                    "present": None,
                    "result": None,
                    "error": base_validation.get("error"),
                }
                self._emit_runner("config-validation", status=base_validation.get("status"), error=base_validation.get("error"))
                self._emit_runner("config-error", error=base_validation.get("error"), violations=base_validation.get("violations"))
                return f"ConfigError:{base_validation.get('error')}"
            merged = dict(base_cfg)
            merged.update(self.config_overlay)
            composed_source: Dict[str, object] = {
                "kind": "composed",
                "base": base_snapshot.get("source"),
                "overlay": self.config_overlay_source,
            }
            cfg_obj, cfg_snapshot, cfg_validation = load_and_validate_config(
                config_json=None,
                config_path=None,
                config_obj=merged,
                config_source=composed_source,
                config_schema=config_schema,  # type: ignore[arg-type]
                repo_root=self.repo_root,
            )
        else:
            cfg_obj, cfg_snapshot, cfg_validation = load_and_validate_config(
                config_json=self.config_json,
                config_path=self.config_path,
                config_obj=None,
                config_source=None,
                config_schema=config_schema,  # type: ignore[arg-type]
                repo_root=self.repo_root,
            )

        self.config_obj = cfg_obj
        self.config_snapshot = cfg_snapshot
        self.config_validation = cfg_validation
        self._emit_runner("config-validation", status=cfg_validation.get("status"), error=cfg_validation.get("error"))
        if cfg_validation.get("status") != "pass":
            self.configure_record = {
                "status": "skipped",
                "present": None,
                "result": None,
                "error": cfg_validation.get("error"),
            }
            self._emit_runner("config-error", error=cfg_validation.get("error"), violations=cfg_validation.get("violations"))
            return f"ConfigError:{cfg_validation.get('error')}"

        try:
            try:
                import frida  # type: ignore
            except Exception as exc:
                self._emit_runner("frida-import-error", error=_stable_error_string(exc))
                self.configure_record = {
                    "status": "skipped",
                    "present": None,
                    "result": None,
                    "error": _stable_error_string(exc),
                }
                return f"FridaImportError:{_stable_error_string(exc)}"

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
                if isinstance(msg, dict):
                    self.writer.emit_agent_message(msg)
                else:
                    self._emit_runner("agent-message-nonobject", msg_type=str(type(msg)))

            self._emit_runner("stage", stage="script-load")
            self.script = self.session.create_script(self.assembled_src.decode("utf-8"))
            self.script.on("message", on_message)
            self.script.load()

            # Configure contract v1: call configure() once, immediately after script.load().
            try:
                result = self.script.exports_sync.configure(self.config_obj)
            except Exception as exc:
                if _looks_like_missing_export(exc, export_name="configure"):
                    if expected_configure_present is True:
                        err = "ConfigureMissingError: configure export absent"
                        self.configure_record = {"status": "fail", "present": False, "result": None, "error": err}
                        self._emit_runner("configure", status="fail", present=False)
                        self._emit_runner("configure-error", error=err)
                        return f"ConfigureError:{err}"
                    self.configure_record = {"status": "absent", "present": False, "result": None, "error": None}
                    self._emit_runner("configure", status="absent", present=False)
                else:
                    err = _stable_error_string(exc)
                    self.configure_record = {"status": "fail", "present": True, "result": None, "error": err}
                    self._emit_runner("configure", status="fail", present=True)
                    self._emit_runner("configure-error", error=err)
                    return f"ConfigureError:{err}"
            else:
                if expected_configure_present is False:
                    err = "ConfigureMismatchError: manifest rpc.configure.present=false but configure export exists"
                    self.configure_record = {"status": "fail", "present": True, "result": None, "error": err}
                    self._emit_runner("configure", status="fail", present=True)
                    self._emit_runner("configure-error", error=err)
                    return f"ConfigureError:{err}"
                if not isinstance(result, dict):
                    err = f"ConfigureTypeError: expected object return, got {type(result).__name__}"
                    self.configure_record = {"status": "fail", "present": True, "result": None, "error": err}
                    self._emit_runner("configure", status="fail", present=True)
                    self._emit_runner("configure-error", error=err)
                    return f"ConfigureError:{err}"
                self.configure_record = {"status": "pass", "present": True, "result": result, "error": None}
                self._emit_runner("configure", status="pass", present=True)
        except Exception as exc:
            self._emit_runner("runner-exception", error=str(exc))
            return f"{type(exc).__name__}: {exc}"
        return None

    def finalize_meta(self, *, world_id: str, attach_meta: Dict[str, object]) -> None:
        try:
            import frida  # type: ignore

            frida_version = getattr(frida, "__version__", None)
        except Exception:
            frida_version = None
        meta = {
            "run_id": self.run_id,
            "world_id": world_id,
            "trace_event_schema": trace_event_schema_stamp(),
            "t0_ns": attach_meta.get("t0_ns"),
            "out_dir": path_utils.to_repo_relative(self.events_path.parent.parent, self.repo_root),
            "host": {
                "platform": platform.platform(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "frida": {
                "python_pkg_version": frida_version,
            },
            "script": {
                "path": path_utils.to_repo_relative(self.script_path, self.repo_root),
                "resolved_path": path_utils.to_repo_relative(self.script_path_resolved, self.repo_root),
                "sha256": sha256_bytes(self.js_src),
                "assembled_sha256": self.assembly_meta.get("assembled_sha256"),
                "assembly_version": self.assembly_meta.get("assembly_version"),
                "helper": self.assembly_meta.get("helper"),
                "manifest": self.manifest_snapshot.get("manifest"),
                "manifest_path": self.manifest_snapshot.get("manifest_path"),
                "manifest_sha256": self.manifest_snapshot.get("manifest_sha256"),
                "manifest_error": self.manifest_snapshot.get("manifest_error"),
                "manifest_violations": self.manifest_snapshot.get("violations"),
                "config": self.config_snapshot,
                "config_validation": self.config_validation,
                "configure": self.configure_record,
            },
            "attach": attach_meta,
        }
        self.meta_path.parent.mkdir(parents=True, exist_ok=True)
        self.meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True))

    def close(self) -> None:
        try:
            if self.session is not None:
                self.session.detach()
        finally:
            self.events_fp.close()
