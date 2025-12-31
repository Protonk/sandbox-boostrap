"""Output layout helpers for Witness runs."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from book.api import path_utils
from book.api.witness.paths import REPO_ROOT


@dataclass(frozen=True)
class OutputSpec:
    """Output configuration for probe runs."""

    out_dir: Optional[Path] = None
    prefix: Optional[str] = None
    log_path: Optional[Path] = None
    record_path: Optional[Path] = None
    observer_path: Optional[Path] = None
    write_stdout_json: bool = True
    write_record_json: bool = True
    json_indent: int = 2
    json_sort_keys: bool = True


@dataclass(frozen=True)
class OutputPaths:
    log_path: Optional[Path]
    record_path: Optional[Path]
    observer_path: Optional[Path]


def _sanitize_label(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return cleaned.strip("_") or "output"


def _build_prefix(plan_id: Optional[str], row_id: Optional[str], probe_id: Optional[str]) -> str:
    parts = [p for p in (plan_id, row_id, probe_id) if p]
    raw = ".".join(parts) if parts else "probe"
    return _sanitize_label(raw)


def _abs_path(path: Optional[Path]) -> Optional[Path]:
    if path is None:
        return None
    return path_utils.ensure_absolute(path, REPO_ROOT)


def resolve_output_paths(
    output: Optional[OutputSpec],
    *,
    plan_id: Optional[str],
    row_id: Optional[str],
    probe_id: Optional[str],
) -> OutputPaths:
    if output is None:
        return OutputPaths(None, None, None)

    out_dir = _abs_path(output.out_dir)
    log_path = _abs_path(output.log_path)
    record_path = _abs_path(output.record_path)
    observer_path = _abs_path(output.observer_path)

    if out_dir is not None:
        prefix = _sanitize_label(output.prefix) if output.prefix else _build_prefix(plan_id, row_id, probe_id)
        if log_path is None and output.write_stdout_json:
            log_path = out_dir / "logs" / f"{prefix}.json"
        if record_path is None and output.write_record_json:
            record_path = out_dir / "records" / f"{prefix}.record.json"
        if observer_path is None and log_path is not None:
            observer_path = log_path.parent / "observer" / f"{log_path.name}.observer.json"
        elif observer_path is None:
            observer_path = out_dir / "observer" / f"{prefix}.observer.json"
    elif observer_path is None and log_path is not None:
        observer_path = log_path.parent / "observer" / f"{log_path.name}.observer.json"

    return OutputPaths(log_path, record_path, observer_path)


def fork_output(output: Optional[OutputSpec], *, prefix: str) -> Optional[OutputSpec]:
    if output is None:
        return None
    use_paths = output.out_dir is None
    return OutputSpec(
        out_dir=output.out_dir,
        prefix=prefix,
        log_path=output.log_path if use_paths else None,
        record_path=output.record_path if use_paths else None,
        observer_path=output.observer_path if use_paths else None,
        write_stdout_json=output.write_stdout_json,
        write_record_json=output.write_record_json,
        json_indent=output.json_indent,
        json_sort_keys=output.json_sort_keys,
    )


def write_json(path: Path, payload: Dict[str, object], *, indent: int, sort_keys: bool) -> Optional[str]:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=indent, sort_keys=sort_keys) + "\n")
        return None
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"
