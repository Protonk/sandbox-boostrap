"""Frida config helpers (headless, deterministic)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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


def _sha256_bytes(blob: bytes) -> str:
    h = hashlib.sha256()
    h.update(blob)
    return h.hexdigest()


def _type_name(value: Any) -> str:
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


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_against_schema(schema: Dict[str, Any], value: Any, path: str) -> List[str]:
    """
    Minimal, deterministic JSON Schema validator used for Frida config.

    Supported keywords:
    - type
    - properties
    - required
    - additionalProperties (bool or schema)
    - items (for arrays)
    - enum
    """
    errors: List[str] = []

    expected_type = schema.get("type")
    if isinstance(expected_type, str):
        if expected_type == "object":
            if not isinstance(value, dict):
                return [f"{path}: expected object, got {_type_name(value)}"]
        elif expected_type == "array":
            if not isinstance(value, list):
                return [f"{path}: expected array, got {_type_name(value)}"]
        elif expected_type == "string":
            if not isinstance(value, str):
                return [f"{path}: expected string, got {_type_name(value)}"]
        elif expected_type == "boolean":
            if not isinstance(value, bool):
                return [f"{path}: expected bool, got {_type_name(value)}"]
        elif expected_type == "integer":
            if not _is_int(value):
                return [f"{path}: expected int, got {_type_name(value)}"]
        elif expected_type == "number":
            if not (_is_int(value) or isinstance(value, float)) or isinstance(value, bool):
                return [f"{path}: expected number, got {_type_name(value)}"]
        elif expected_type == "null":
            if value is not None:
                return [f"{path}: expected null, got {_type_name(value)}"]

    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        if value not in enum:
            return [f"{path}: value not in enum"]

    if expected_type == "object" and isinstance(value, dict):
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            properties = {}
        required = schema.get("required")
        if not isinstance(required, list):
            required = []
        for req in sorted({r for r in required if isinstance(r, str) and r}):
            if req not in value:
                errors.append(f"{path}: missing required property {req}")

        additional = schema.get("additionalProperties", True)
        for key in sorted(value.keys()):
            key_path = f"{path}.{key}"
            if key in properties and isinstance(properties[key], dict):
                errors.extend(_validate_against_schema(properties[key], value[key], key_path))
                continue
            if additional is False:
                errors.append(f"{path}: unexpected property {key}")
                continue
            if isinstance(additional, dict):
                errors.extend(_validate_against_schema(additional, value[key], key_path))

    if expected_type == "array" and isinstance(value, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for i, item in enumerate(value):
                errors.extend(_validate_against_schema(items, item, f"{path}[{i}]"))

    return errors


def _stable_json_error(exc: json.JSONDecodeError) -> str:
    msg = " ".join(str(exc.msg).split())
    return f"JSONDecodeError: {msg} (line {exc.lineno} col {exc.colno})"


def load_and_validate_config(
    *,
    config_json: Optional[str],
    config_path: Optional[str],
    config_obj: Optional[Dict[str, object]],
    config_source: Optional[Dict[str, object]],
    config_schema: Dict[str, Any],
    repo_root: Path,
) -> Tuple[Dict[str, object], Dict[str, object], Dict[str, object]]:
    """
    Load + validate config in a headless, deterministic way.

    Inputs are mutually exclusive: at most one of (config_json, config_path, config_obj) may be provided.

    Returns (config_obj, config_snapshot, config_validation):
    - config_obj: dict (defaults to {})
    - config_snapshot: {"source": {...}, "value": <dict>}
    - config_validation: {"status": "pass"|"fail", "error": <str|null>, "violations": [..]}
    """
    provided = int(config_json is not None) + int(config_path is not None) + int(config_obj is not None)
    if provided > 1:
        empty: Dict[str, object] = {}
        return (
            empty,
            {"source": {"kind": "invalid"}, "value": empty},
            {
                "status": "fail",
                "error": "ConfigInputError: provide at most one of config_json/config_path/config_obj",
                "violations": [],
            },
        )

    cfg: Dict[str, object] = {}
    source: Dict[str, object] = {"kind": "none"}

    if config_obj is not None:
        if not isinstance(config_obj, dict):
            return (
                {},
                {"source": {"kind": "object"}, "value": {}},
                {
                    "status": "fail",
                    "error": f"ConfigTypeError: expected object, got {_type_name(config_obj)}",
                    "violations": [],
                },
            )
        cfg = dict(config_obj)
        source = dict(config_source) if isinstance(config_source, dict) else {"kind": "object"}
    elif config_json is not None:
        try:
            loaded = json.loads(config_json)
        except json.JSONDecodeError as exc:
            return (
                {},
                {"source": {"kind": "inline"}, "value": {}},
                {"status": "fail", "error": _stable_json_error(exc), "violations": []},
            )
        except Exception as exc:
            return (
                {},
                {"source": {"kind": "inline"}, "value": {}},
                {"status": "fail", "error": f"{type(exc).__name__}: {exc}", "violations": []},
            )
        if not isinstance(loaded, dict):
            return (
                {},
                {"source": {"kind": "inline"}, "value": {}},
                {"status": "fail", "error": f"ConfigTypeError: expected object, got {_type_name(loaded)}", "violations": []},
            )
        cfg = loaded
        source = {"kind": "inline", "sha256": _sha256_bytes(config_json.encode("utf-8"))}
    elif config_path is not None:
        config_abs = path_utils.ensure_absolute(config_path, repo_root)
        try:
            raw = config_abs.read_bytes()
        except Exception as exc:
            return (
                {},
                {
                    "source": {"kind": "file", "path": path_utils.to_repo_relative(config_abs, repo_root)},
                    "value": {},
                },
                {
                    "status": "fail",
                    "error": f"ConfigReadError: {path_utils.to_repo_relative(config_abs, repo_root)}: {type(exc).__name__}: {exc}",
                    "violations": [],
                },
            )
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError as exc:
            return (
                {},
                {"source": {"kind": "file", "path": path_utils.to_repo_relative(config_abs, repo_root)}, "value": {}},
                {"status": "fail", "error": _stable_json_error(exc), "violations": []},
            )
        except Exception as exc:
            return (
                {},
                {"source": {"kind": "file", "path": path_utils.to_repo_relative(config_abs, repo_root)}, "value": {}},
                {"status": "fail", "error": f"{type(exc).__name__}: {exc}", "violations": []},
            )
        if not isinstance(loaded, dict):
            return (
                {},
                {"source": {"kind": "file", "path": path_utils.to_repo_relative(config_abs, repo_root)}, "value": {}},
                {"status": "fail", "error": f"ConfigTypeError: expected object, got {_type_name(loaded)}", "violations": []},
            )
        cfg = loaded
        source = {
            "kind": "file",
            "path": path_utils.to_repo_relative(config_abs, repo_root),
            "sha256": _sha256_bytes(raw),
        }

    if not isinstance(config_schema, dict):
        snapshot = {"source": source, "value": cfg}
        return (
            cfg,
            snapshot,
            {"status": "fail", "error": "ConfigSchemaError: missing/invalid config schema", "violations": []},
        )

    violations = _validate_against_schema(config_schema, cfg, "$")
    if violations:
        first = violations[0]
        snapshot = {"source": source, "value": cfg}
        return (
            cfg,
            snapshot,
            {"status": "fail", "error": f"ConfigSchemaMismatch: {first}", "violations": violations},
        )
    snapshot = {"source": source, "value": cfg}
    return cfg, snapshot, {"status": "pass", "error": None, "violations": []}
