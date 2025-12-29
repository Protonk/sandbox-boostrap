"""Frida attach helper with JSONL event capture."""

from __future__ import annotations

import hashlib
import json
import platform
import time
from pathlib import Path
from typing import Dict, Optional

import frida

from book.api import path_utils


def sha256_bytes(blob: bytes) -> str:
    h = hashlib.sha256()
    h.update(blob)
    return h.hexdigest()


def now_ns() -> int:
    return time.time_ns()


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
        self.meta_path.parent.mkdir(parents=True, exist_ok=True)
        self.meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True))

    def close(self) -> None:
        try:
            if self.session is not None:
                self.session.detach()
        finally:
            self.events_fp.close()
