"""Fixer registry and runner for CARTON."""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Iterable, List, Optional

from book.integration.carton import paths
from book.integration.carton import spec as spec_mod


def _repo_root() -> Path:
    return paths.repo_root()


def load_fixer_entries(*, repo_root: Optional[Path] = None) -> List[dict]:
    root = repo_root or _repo_root()
    spec_path = paths.ensure_absolute(paths.FIXERS_SPEC, repo_root_path=root)
    spec = spec_mod.load_fixers_spec(spec_path)
    return spec.get("fixers") or []


def _select_fixers(entries: List[dict], ids: Optional[Iterable[str]]) -> List[dict]:
    if not ids:
        return entries
    want = {i for i in ids if i}
    selected = [entry for entry in entries if entry.get("id") in want]
    missing = want - {entry.get("id") for entry in selected}
    if missing:
        raise ValueError(f"unknown fixer ids: {sorted(missing)}")
    return selected


def run_fixers(*, ids: Optional[Iterable[str]] = None, repo_root: Optional[Path] = None) -> List[str]:
    root = repo_root or _repo_root()
    entries = _select_fixers(load_fixer_entries(repo_root=root), ids)
    outputs: List[str] = []
    for entry in entries:
        module_name = entry.get("module")
        func_name = entry.get("function")
        fixer_id = entry.get("id")
        module = importlib.import_module(module_name)
        func = getattr(module, func_name)
        print(f"[carton] fixer {fixer_id}: {module_name}.{func_name}")
        func()
        for out in entry.get("outputs") or []:
            out_path = paths.ensure_absolute(out, repo_root_path=root)
            if not out_path.exists():
                raise FileNotFoundError(f"fixer {fixer_id} did not write output: {out}")
            outputs.append(paths.repo_relative(out_path, repo_root_path=root))
    return outputs
