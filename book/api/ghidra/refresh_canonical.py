"""Refresh canonical Ghidra sentinel fixtures from existing outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from book.api import path_utils


SENTINELS = {
    "offset_inst_scan_0xc0_write_classify": {
        "fixture_path": "book/tests/fixtures/ghidra_canonical/offset_inst_scan_0xc0_write_classify.json",
        "meta_path": "book/tests/fixtures/ghidra_canonical/offset_inst_scan_0xc0_write_classify.meta.json",
        "output_path": "dumps/ghidra/out/14.4.1-23E224/kernel-collection-offset-scan-0xc0-write-classify/offset_inst_scan.json",
        "script_path": "book/api/ghidra/scripts/kernel_offset_inst_scan.py",
        "deps": [
            "book/api/ghidra/scripts/ghidra_bootstrap.py",
            "book/api/ghidra/ghidra_lib/scan_utils.py",
        ],
        "program_path": "dumps/Sandbox-private/14.4.1-23E224/kernel/BootKernelCollection.kc",
        "normalizer_id": "offset_inst_scan_normalizer_v1",
        "ghidra_version": "11.4.2",
    },
}


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _hex_int(value: str) -> int:
    return int(str(value), 16)


def _bool_str(value: bool) -> str:
    return "true" if value else "false"


def _normalize_offset_inst_scan(payload: dict) -> dict:
    meta = dict(payload.get("meta", {}))
    hits = list(payload.get("hits", []))
    block_filter = list(meta.get("block_filter") or [])

    def block_key(entry: dict) -> tuple[int, int, str]:
        start = entry.get("start")
        end = entry.get("end")
        name = entry.get("name") or ""
        return (_hex_int(start) if start else 0, _hex_int(end) if end else 0, name)

    meta["block_filter"] = sorted(block_filter, key=block_key)

    def hit_key(entry: dict) -> tuple[int, str, str]:
        addr = entry.get("address")
        mnemonic = entry.get("mnemonic") or ""
        inst = entry.get("inst") or ""
        return (_hex_int(addr) if addr else 0, mnemonic, inst)

    hits_sorted = sorted(hits, key=hit_key)
    return {"meta": meta, "hits": hits_sorted}


def _build_profile_id(meta: dict) -> str:
    return (
        "kernel_offset_inst_scan:offset=%s:write=%s:all=%s:exact=%s:canonical=%s:classify=%s:skip_stack=%s"
        % (
            meta.get("offset"),
            _bool_str(bool(meta.get("write_only"))),
            _bool_str(bool(meta.get("scan_all_blocks"))),
            _bool_str(bool(meta.get("exact_match"))),
            _bool_str(bool(meta.get("include_canonical"))),
            _bool_str(bool(meta.get("include_access"))),
            _bool_str(bool(meta.get("skip_stack"))),
        )
    )


def _load_json(path: Path) -> dict:
    with path.open("r") as f:
        return json.load(f)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")


def _resolve_paths(entry: dict, repo_root: Path) -> Dict[str, Path]:
    return {
        "fixture": path_utils.ensure_absolute(entry["fixture_path"], repo_root),
        "meta": path_utils.ensure_absolute(entry["meta_path"], repo_root),
        "output": path_utils.ensure_absolute(entry["output_path"], repo_root),
        "script": path_utils.ensure_absolute(entry["script_path"], repo_root),
        "program": path_utils.ensure_absolute(entry["program_path"], repo_root),
    }


def _build_deps(entry: dict, repo_root: Path) -> List[dict]:
    deps = []
    for dep_path in entry.get("deps", []):
        dep_abs = path_utils.ensure_absolute(dep_path, repo_root)
        deps.append(
            {
                "path": path_utils.to_repo_relative(dep_abs, repo_root),
                "sha256": _sha256_path(dep_abs),
            }
        )
    return deps


def refresh(name: str) -> None:
    if name not in SENTINELS:
        raise SystemExit(f"unknown sentinel: {name}")
    repo_root = path_utils.find_repo_root()
    entry = SENTINELS[name]
    paths = _resolve_paths(entry, repo_root)

    output_payload = _load_json(paths["output"])
    provenance = output_payload.get("_provenance")
    if provenance is None:
        raise SystemExit("output is missing _provenance; re-run the Ghidra task first")

    normalized = _normalize_offset_inst_scan(output_payload)
    _write_json(paths["fixture"], normalized)

    world_path = repo_root / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"
    world = _load_json(world_path)
    profile_id = provenance.get("analysis", {}).get("profile_id") or _build_profile_id(normalized["meta"])

    meta = {
        "world_id": world.get("world_id"),
        "normalizer_id": entry.get("normalizer_id"),
        "generator": {
            "script_path": path_utils.to_repo_relative(paths["script"], repo_root),
            "script_content_sha256": _sha256_path(paths["script"]),
            "runner_version": "book.api.ghidra.scaffold",
            "deps": _build_deps(entry, repo_root),
        },
        "ghidra": {
            "version": entry.get("ghidra_version"),
        },
        "analysis": {
            "profile_id": profile_id,
        },
        "input": {
            "program_path": path_utils.to_repo_relative(paths["program"], repo_root),
            "program_sha256": _sha256_path(paths["program"]),
        },
        "output": {
            "path": path_utils.to_repo_relative(paths["output"], repo_root),
            "normalized_sha256": _sha256_path(paths["fixture"]),
        },
    }
    _write_json(paths["meta"], meta)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Refresh canonical Ghidra sentinel fixtures")
    parser.add_argument("--name", required=True, help="Sentinel name")
    args = parser.parse_args(argv)

    refresh(args.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
