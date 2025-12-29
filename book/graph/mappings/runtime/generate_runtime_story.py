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
from book.api.runtime.mapping import story as rt_story

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import promotion_packets

CUT_ROOT = ROOT / "book" / "graph" / "mappings" / "runtime_cuts"


def sha256_path(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def generate(packet_paths: list[Path] | None = None) -> Path:
    manifest_path = CUT_ROOT / "runtime_manifest.json"
    if not manifest_path.exists():
        raise SystemExit(f"missing runtime manifest at {manifest_path}; run promotion first")

    manifest = json.loads(manifest_path.read_text())
    scenarios_path = path_utils.ensure_absolute(manifest.get("scenarios"), ROOT)
    ops_path = path_utils.ensure_absolute(manifest.get("ops"), ROOT)

    packets = promotion_packets.load_packets(
        packet_paths or promotion_packets.DEFAULT_PACKET_PATHS,
        allow_missing=True,
    )
    for packet in packets:
        promotion_packets.require_clean_manifest(packet, str(packet.packet_path))

    story = rt_story.build_story(ops_path, scenarios_path)
    inputs = [
        path_utils.to_repo_relative(ops_path, ROOT),
        path_utils.to_repo_relative(scenarios_path, ROOT),
    ]
    input_hashes = {
        inputs[0]: sha256_path(ops_path),
        inputs[1]: sha256_path(scenarios_path),
    }
    run_manifest_inputs = []
    run_ids = []
    repo_root_contexts = []
    for packet in packets:
        rel_packet = path_utils.to_repo_relative(packet.packet_path, ROOT)
        inputs.append(rel_packet)
        input_hashes[rel_packet] = sha256_path(packet.packet_path)
        packet_manifest_path = packet.paths.get("run_manifest")
        if packet_manifest_path:
            rel_manifest = path_utils.to_repo_relative(packet_manifest_path, ROOT)
            run_manifest_inputs.append(rel_manifest)
            input_hashes[rel_manifest] = sha256_path(packet_manifest_path)
        if packet.run_manifest.get("run_id"):
            run_ids.append(packet.run_manifest.get("run_id"))
        if packet.run_manifest.get("repo_root_context"):
            repo_root_contexts.append(packet.run_manifest.get("repo_root_context"))
    meta = story.get("meta", {})
    meta["inputs"] = inputs
    meta["input_hashes"] = input_hashes
    meta["run_provenance"] = {
        "run_ids": run_ids,
        "manifests": run_manifest_inputs,
        "repo_root_contexts": repo_root_contexts,
    }
    manifest_meta = manifest.get("meta") or {}
    if manifest_meta.get("source_jobs"):
        meta["source_jobs"] = manifest_meta["source_jobs"]
    note = meta.get("notes") or ""
    if "promotion packet" not in note:
        meta["notes"] = (note + " " if note else "") + "Inputs derived from promotion packets."
    story["meta"] = meta
    out_path = CUT_ROOT / "runtime_story.json"
    rt_story.write_story(story, out_path)

    manifest["runtime_story"] = path_utils.to_repo_relative(out_path, ROOT)
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"[+] wrote runtime story to {out_path}")
    return out_path


def main() -> None:
    generate()


if __name__ == "__main__":
    main()
