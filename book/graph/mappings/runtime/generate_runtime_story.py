#!/usr/bin/env python3
"""
Generate a joined per-op runtime story from the latest runtime cut.

Reads the canonical op/scenario mappings from book/graph/mappings/runtime_cuts/
and emits runtime_story.json alongside them. Updates runtime_manifest.json to
include a pointer to the story file so loaders can discover it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import path_utils
from book.api.runtime_tools import runtime_story as rt_story

CUT_ROOT = ROOT / "book" / "graph" / "mappings" / "runtime_cuts"


def sha256_path(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    manifest_path = CUT_ROOT / "runtime_manifest.json"
    if not manifest_path.exists():
        raise SystemExit(f"missing runtime manifest at {manifest_path}; run promotion first")

    manifest = json.loads(manifest_path.read_text())
    scenarios_path = path_utils.ensure_absolute(manifest.get("scenarios"), ROOT)
    ops_path = path_utils.ensure_absolute(manifest.get("ops"), ROOT)

    story = rt_story.build_runtime_story(ops_path, scenarios_path)
    inputs = [
        path_utils.to_repo_relative(ops_path, ROOT),
        path_utils.to_repo_relative(scenarios_path, ROOT),
    ]
    input_hashes = {
        inputs[0]: sha256_path(ops_path),
        inputs[1]: sha256_path(scenarios_path),
    }
    meta = story.get("meta", {})
    meta["inputs"] = inputs
    meta["input_hashes"] = input_hashes
    manifest_meta = manifest.get("meta") or {}
    if manifest_meta.get("source_jobs"):
        meta["source_jobs"] = manifest_meta["source_jobs"]
    story["meta"] = meta
    out_path = CUT_ROOT / "runtime_story.json"
    rt_story.write_runtime_story(story, out_path)

    manifest["runtime_story"] = path_utils.to_repo_relative(out_path, ROOT)
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"[+] wrote runtime story to {out_path}")


if __name__ == "__main__":
    main()
