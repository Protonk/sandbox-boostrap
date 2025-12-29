"""Frida config helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional

from book.api import path_utils


def load_frida_config(
    *,
    config_json: Optional[str],
    config_path: Optional[str],
    repo_root: Path,
) -> Optional[Dict[str, object]]:
    if config_json and config_path:
        raise SystemExit("use only one of --frida-config or --frida-config-path")
    config = None
    if config_json:
        try:
            config = json.loads(config_json)
        except Exception as exc:
            raise SystemExit(f"invalid --frida-config JSON: {exc}")
    elif config_path:
        config_abs = path_utils.ensure_absolute(config_path, repo_root)
        try:
            config = json.loads(config_abs.read_text())
        except Exception as exc:
            raise SystemExit(f"invalid --frida-config-path JSON: {exc}")
    if config is None:
        return None
    if not isinstance(config, dict):
        raise SystemExit("frida config must be a JSON object")
    return config
