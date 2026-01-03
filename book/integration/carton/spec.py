"""Load and validate CARTON specs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import re

from book.integration.carton import paths

HASH_MODES = {"bytes", "semantic_json", "presence_only"}
_CONTRACT_TOKEN_RE = re.compile(r"(?i)(?:^|/)[^/]*(spec\\.|schema\\.)")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def load_carton_spec(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing CARTON spec: {path}")
    spec = _load_json(path)
    if not isinstance(spec, dict):
        raise ValueError("carton_spec.json must be a JSON object")
    if "artifacts" not in spec or not isinstance(spec["artifacts"], list):
        raise ValueError("carton_spec.json must include an artifacts list")
    seen_ids = set()
    for entry in spec["artifacts"]:
        if not isinstance(entry, dict):
            raise ValueError("carton_spec.json artifacts entries must be objects")
        for key in ("id", "path", "role", "hash_mode"):
            if key not in entry:
                raise ValueError(f"carton_spec.json artifact missing {key}: {entry}")
        if entry["id"] in seen_ids:
            raise ValueError(f"carton_spec.json has duplicate artifact id: {entry['id']}")
        seen_ids.add(entry["id"])
        if entry["hash_mode"] not in HASH_MODES:
            raise ValueError(f"unsupported hash_mode {entry['hash_mode']} for {entry['id']}")
        if Path(entry["path"]).is_absolute():
            raise ValueError(f"artifact path must be repo-relative: {entry['path']}")
    return spec


def load_fixers_spec(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing fixers spec: {path}")
    spec = _load_json(path)
    if not isinstance(spec, dict):
        raise ValueError("fixers.json must be a JSON object")
    if "fixers" not in spec or not isinstance(spec["fixers"], list):
        raise ValueError("fixers.json must include a fixers list")
    seen_ids = set()
    for entry in spec["fixers"]:
        if not isinstance(entry, dict):
            raise ValueError("fixers.json entries must be objects")
        for key in ("id", "module", "function", "outputs"):
            if key not in entry:
                raise ValueError(f"fixers.json entry missing {key}: {entry}")
        if entry["id"] in seen_ids:
            raise ValueError(f"fixers.json has duplicate fixer id: {entry['id']}")
        seen_ids.add(entry["id"])
        outputs = entry.get("outputs")
        if not isinstance(outputs, list) or not outputs:
            raise ValueError(f"fixer outputs must be a non-empty list: {entry['id']}")
        for out in outputs:
            if not isinstance(out, str) or not out:
                raise ValueError(f"invalid fixer output path for {entry['id']}: {out!r}")
            if Path(out).is_absolute():
                raise ValueError(f"fixer output must be repo-relative: {out}")
    return spec


def load_invariants(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing invariants spec: {path}")
    data = _load_json(path)
    if not isinstance(data, dict):
        raise ValueError("invariants.json must be a JSON object")
    return data


def is_contract_path(path: str | Path) -> bool:
    return bool(_CONTRACT_TOKEN_RE.search(str(path)))


def default_carton_spec_path() -> Path:
    return paths.ensure_absolute(paths.CARTON_SPEC)


def default_fixers_spec_path() -> Path:
    return paths.ensure_absolute(paths.FIXERS_SPEC)


def default_invariants_path() -> Path:
    return paths.ensure_absolute(paths.INVARIANTS_SPEC)
