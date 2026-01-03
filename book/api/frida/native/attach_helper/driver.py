"""Embedded Python entrypoint for the signed Frida attach helper."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import uuid
from pathlib import Path
from typing import Dict, Optional

from book.api import path_utils
from book.api.frida.capture import FridaCapture
from book.api.profile.identity import baseline_world_id


def _emit(payload: Dict[str, object]) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def _load_json_arg(value: Optional[str], *, label: str) -> Optional[Dict[str, object]]:
    if value is None:
        return None
    try:
        obj = json.loads(value)
    except Exception as exc:
        raise SystemExit(f"{label} invalid json: {exc}")
    if not isinstance(obj, dict):
        raise SystemExit(f"{label} must be a JSON object")
    return obj


def _load_json_path(path: Optional[str], *, label: str, repo_root: Path) -> Optional[Dict[str, object]]:
    if path is None:
        return None
    abs_path = path_utils.ensure_absolute(path, repo_root)
    try:
        obj = json.loads(abs_path.read_text())
    except Exception as exc:
        raise SystemExit(f"{label} could not read: {exc}")
    if not isinstance(obj, dict):
        raise SystemExit(f"{label} must be a JSON object")
    return obj


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--script", required=True)
    ap.add_argument("--events", required=True)
    ap.add_argument("--meta", required=True)
    ap.add_argument("--run-id")
    ap.add_argument("--repo-root")
    ap.add_argument("--config-json")
    ap.add_argument("--config-path")
    ap.add_argument("--config-overlay")
    ap.add_argument("--config-overlay-path")
    return ap


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    repo_root = path_utils.ensure_absolute(args.repo_root, None) if args.repo_root else path_utils.find_repo_root()

    run_id = args.run_id or str(uuid.uuid4())
    script_path = path_utils.ensure_absolute(args.script, repo_root)
    events_path = path_utils.ensure_absolute(args.events, repo_root)
    meta_path = path_utils.ensure_absolute(args.meta, repo_root)
    events_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.parent.mkdir(parents=True, exist_ok=True)

    config_overlay = _load_json_arg(args.config_overlay, label="config_overlay") or {}
    config_overlay_path = _load_json_path(
        args.config_overlay_path, label="config_overlay_path", repo_root=repo_root
    )
    if config_overlay_path:
        config_overlay.update(config_overlay_path)

    capture = FridaCapture(
        run_id=run_id,
        pid=args.pid,
        script_path=script_path,
        events_path=events_path,
        meta_path=meta_path,
        config_json=args.config_json,
        config_path=args.config_path,
        config_overlay=config_overlay or None,
        config_overlay_source={"kind": "helper"} if config_overlay else None,
        repo_root=repo_root,
    )

    stop = False

    def _handle_signal(signum, frame) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        error = capture.attach()
        if error:
            _emit({"kind": "attach_error", "error": error})
            return 1
        _emit(
            {
                "kind": "attach_ready",
                "pid": args.pid,
                "run_id": run_id,
                "events_path": path_utils.to_repo_relative(events_path, repo_root),
                "meta_path": path_utils.to_repo_relative(meta_path, repo_root),
            }
        )
        for raw in sys.stdin:
            if stop:
                break
            line = raw.strip()
            if not line:
                continue
            try:
                cmd = json.loads(line)
            except Exception as exc:
                _emit({"kind": "command_error", "error": f"invalid json: {exc}"})
                continue
            if not isinstance(cmd, dict):
                _emit({"kind": "command_error", "error": "command must be a JSON object"})
                continue
            cmd_type = cmd.get("type")
            if cmd_type == "finalize":
                attach_meta = cmd.get("attach_meta")
                if not isinstance(attach_meta, dict):
                    _emit({"kind": "finalize_error", "error": "attach_meta must be a JSON object"})
                    continue
                world_id = cmd.get("world_id")
                if not isinstance(world_id, str):
                    world_id = baseline_world_id(repo_root)
                try:
                    capture.finalize_meta(world_id=world_id, attach_meta=attach_meta)
                except Exception as exc:
                    _emit({"kind": "finalize_error", "error": f"{type(exc).__name__}: {exc}"})
                    continue
                _emit({"kind": "finalize_ok", "meta_path": path_utils.to_repo_relative(meta_path, repo_root)})
                continue
            if cmd_type == "close":
                _emit({"kind": "close_ok"})
                break
            if cmd_type == "ping":
                _emit({"kind": "pong"})
                continue
            _emit({"kind": "command_error", "error": f"unknown command: {cmd_type}"})
    finally:
        capture.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
