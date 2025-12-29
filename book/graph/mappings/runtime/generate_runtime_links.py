#!/usr/bin/env python3
"""
Generate runtime_links.json to cross-link runtime evidence to static mappings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import path_utils
from book.api import world as world_mod
from book.api.runtime.analysis.mapping import build as mapping_build

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import promotion_packets

OUT = ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_links.json"

OPS_VOCAB = ROOT / "book" / "graph" / "mappings" / "vocab" / "ops.json"
OPS_COVERAGE = ROOT / "book" / "graph" / "mappings" / "vocab" / "ops_coverage.json"
TAG_LAYOUTS = ROOT / "book" / "graph" / "mappings" / "tag_layouts" / "tag_layouts.json"
SYSTEM_DIGESTS = ROOT / "book" / "graph" / "mappings" / "system_profiles" / "digests.json"
RUNTIME_SIGNATURES = ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_signatures.json"
OP_SUMMARY = ROOT / "book" / "graph" / "mappings" / "runtime" / "op_runtime_summary.json"
ORACLE = ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_callout_oracle.json"

LINKS_SCHEMA_VERSION = "runtime-links.v0.1"


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def baseline_world() -> str:
    data, resolution = world_mod.load_world(repo_root=ROOT)
    return world_mod.require_world_id(data, world_path=resolution.entry.world_path)


def _ops_vocab_index() -> Dict[str, str]:
    ops_doc = _load_json(OPS_VOCAB)
    ops = ops_doc.get("ops") or []
    return {entry.get("name"): entry.get("id") for entry in ops if isinstance(entry, dict)}


def _add_input(path: Path, inputs: List[str], input_hashes: Dict[str, str]) -> None:
    rel = path_utils.to_repo_relative(path, repo_root=ROOT)
    if rel in input_hashes:
        return
    inputs.append(rel)
    input_hashes[rel] = _sha256_path(path)


def _path_info(path: Path) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "path": path_utils.to_repo_relative(path, repo_root=ROOT),
        "exists": path.exists(),
    }
    if path.exists() and path.is_file():
        info["sha256"] = _sha256_path(path)
        info["size"] = path.stat().st_size
    return info


def _find_compiled_blob(profile_path: Path, run_dir: Optional[Path]) -> Optional[Path]:
    if profile_path.suffix == ".bin":
        return profile_path
    if not run_dir:
        return None
    candidate = run_dir / "sb_build" / f"{profile_path.stem}.sb.bin"
    if candidate.exists():
        return candidate
    return None


def _runtime_profile_path(profile_path: Path, profile_id: str, run_dir: Optional[Path]) -> Optional[Path]:
    if not run_dir:
        return None
    runtime_dir = run_dir / "runtime_profiles"
    if not runtime_dir.exists():
        return None
    stem = profile_path.stem
    suffix = profile_id.replace(":", "_")
    candidate = runtime_dir / f"{stem}.{suffix}.runtime.sb"
    if candidate.exists():
        return candidate
    return None


def generate(packet_paths: Optional[List[Path]] = None) -> Path:
    world_id = baseline_world()
    packets = promotion_packets.load_packets(packet_paths or promotion_packets.DEFAULT_PACKET_PATHS, allow_missing=True)
    for packet in packets:
        promotion_packets.require_clean_manifest(packet, str(packet.packet_path))

    ops_index = _ops_vocab_index()
    system_digests = _load_json(SYSTEM_DIGESTS).get("profiles") or {}

    inputs: List[str] = []
    input_hashes: Dict[str, str] = {}
    packet_index: Dict[str, Any] = {}
    profiles: Dict[str, Any] = {}
    expectations: Dict[str, Any] = {}

    for packet in packets:
        packet_path = packet.packet_path
        packet_rel = path_utils.to_repo_relative(packet_path, repo_root=ROOT)

        run_manifest_path = path_utils.ensure_absolute(Path(packet.packet.get("run_manifest")), ROOT)
        expected_matrix_path = packet.paths["expected_matrix"]
        runtime_events_path = packet.paths["runtime_events"]

        _add_input(packet_path, inputs, input_hashes)
        _add_input(run_manifest_path, inputs, input_hashes)
        _add_input(expected_matrix_path, inputs, input_hashes)
        _add_input(runtime_events_path, inputs, input_hashes)

        run_manifest = packet.run_manifest
        run_id = run_manifest.get("run_id")
        output_root = run_manifest.get("output_root")
        run_dir: Optional[Path] = None
        if run_id and output_root:
            output_root_path = path_utils.ensure_absolute(Path(output_root), ROOT)
            run_dir = output_root_path / str(run_id)

        packet_index[packet_rel] = {
            "run_id": run_id,
            "run_manifest": path_utils.to_repo_relative(run_manifest_path, repo_root=ROOT),
            "expected_matrix": path_utils.to_repo_relative(expected_matrix_path, repo_root=ROOT),
            "runtime_events": path_utils.to_repo_relative(runtime_events_path, repo_root=ROOT),
            "runtime_results": path_utils.to_repo_relative(packet.paths["runtime_results"], repo_root=ROOT),
            "baseline_results": path_utils.to_repo_relative(packet.paths["baseline_results"], repo_root=ROOT)
            if packet.paths.get("baseline_results")
            else None,
            "oracle_results": path_utils.to_repo_relative(packet.paths["oracle_results"], repo_root=ROOT)
            if packet.paths.get("oracle_results")
            else None,
            "output_root": output_root,
            "sb_build_dir": path_utils.to_repo_relative(run_dir / "sb_build", repo_root=ROOT)
            if run_dir and (run_dir / "sb_build").exists()
            else None,
            "runtime_profiles_dir": path_utils.to_repo_relative(run_dir / "runtime_profiles", repo_root=ROOT)
            if run_dir and (run_dir / "runtime_profiles").exists()
            else None,
        }

        expected_matrix = _load_json(expected_matrix_path)
        packet_world_id = expected_matrix.get("world_id") or run_manifest.get("world_id")
        if packet_world_id and packet_world_id != world_id:
            raise ValueError(f"world_id mismatch: {packet_world_id} vs {world_id}")

        for profile_id, profile in (expected_matrix.get("profiles") or {}).items():
            if not isinstance(profile, dict):
                continue
            profile_path_raw = profile.get("blob")
            if not profile_path_raw:
                continue
            profile_path = path_utils.ensure_absolute(Path(profile_path_raw), ROOT)
            profile_rel = path_utils.to_repo_relative(profile_path, repo_root=ROOT)

            entry = profiles.setdefault(
                profile_id,
                {
                    "profile_id": profile_id,
                    "profile_path": profile_rel,
                    "profile_mode": profile.get("mode"),
                    "family": profile.get("family"),
                    "semantic_group": profile.get("semantic_group"),
                    "expected_ops": set(),
                    "observed_ops": set(),
                    "expectation_ids": [],
                    "scenario_ids": set(),
                    "observed_expectation_ids": set(),
                    "observation_counts": {"total": 0, "blocked": 0, "blocked_by_stage": {}},
                    "source_packets": set(),
                    "expected_matrix_sources": set(),
                },
            )

            if entry["profile_path"] != profile_rel:
                raise ValueError(f"profile path mismatch for {profile_id}")
            if entry.get("profile_mode") != profile.get("mode"):
                raise ValueError(f"profile mode mismatch for {profile_id}")

            entry["source_packets"].add(packet_rel)
            entry["expected_matrix_sources"].add(
                path_utils.to_repo_relative(expected_matrix_path, repo_root=ROOT)
            )

            for probe in profile.get("probes") or []:
                expectation_id = probe.get("expectation_id")
                op_name = probe.get("operation")
                if not expectation_id or not op_name:
                    continue
                if op_name not in ops_index:
                    raise ValueError(f"unknown operation in expected_matrix: {op_name}")
                expectation_doc = {
                    "expectation_id": expectation_id,
                    "profile_id": profile_id,
                    "operation": op_name,
                    "op_id": ops_index.get(op_name),
                    "expected": probe.get("expected"),
                    "target": probe.get("target"),
                    "driver": probe.get("driver"),
                    "source_packet": packet_rel,
                    "expected_matrix": path_utils.to_repo_relative(expected_matrix_path, repo_root=ROOT),
                }
                existing = expectations.get(expectation_id)
                if existing and existing != expectation_doc:
                    raise ValueError(f"expectation mismatch: {expectation_id}")
                expectations[expectation_id] = expectation_doc
                if expectation_id not in entry["expectation_ids"]:
                    entry["expectation_ids"].append(expectation_id)
                entry["expected_ops"].add(op_name)

            compiled_blob = _find_compiled_blob(profile_path, run_dir)
            if compiled_blob:
                entry["compiled_blob"] = _path_info(compiled_blob)
            runtime_profile = _runtime_profile_path(profile_path, profile_id, run_dir)
            if runtime_profile:
                entry["runtime_profile"] = _path_info(runtime_profile)
            entry["profile_source"] = _path_info(profile_path)

            digest = system_digests.get(profile_id)
            if digest:
                entry["system_profile_digest_id"] = profile_id
                entry["system_profile_digest"] = {
                    "status": digest.get("status"),
                    "observed": digest.get("observed"),
                    "source": digest.get("source"),
                }

        observations = promotion_packets.load_observations(packet)
        for obs in observations:
            if obs.operation and obs.operation not in ops_index:
                raise ValueError(f"unknown operation in runtime_events: {obs.operation}")
            entry = profiles.get(obs.profile_id)
            if not entry:
                continue
            entry["observation_counts"]["total"] += 1
            if obs.operation:
                entry["observed_ops"].add(obs.operation)
            if obs.scenario_id:
                entry["scenario_ids"].add(obs.scenario_id)
            if obs.expectation_id:
                entry["observed_expectation_ids"].add(obs.expectation_id)
            if (obs.failure_stage or "probe") in {"apply", "bootstrap", "preflight"}:
                entry["observation_counts"]["blocked"] += 1
                stage = obs.failure_stage or "unknown"
                blocked = entry["observation_counts"]["blocked_by_stage"]
                blocked[stage] = int(blocked.get(stage, 0)) + 1

    for entry in profiles.values():
        entry["expected_ops"] = sorted(entry["expected_ops"])
        entry["observed_ops"] = sorted(entry["observed_ops"])
        entry["scenario_ids"] = sorted(entry["scenario_ids"])
        entry["source_packets"] = sorted(entry["source_packets"])
        entry["expected_matrix_sources"] = sorted(entry["expected_matrix_sources"])
        entry["observed_expectation_ids"] = sorted(entry["observed_expectation_ids"])
        entry["op_ids"] = {name: ops_index.get(name) for name in entry["expected_ops"]}

    meta = mapping_build.mapping_metadata(
        world_id,
        schema_version=LINKS_SCHEMA_VERSION,
        status="partial",
        notes="Cross-links runtime observations to profiles, static mappings, and oracle lanes.",
    )
    meta["inputs"] = inputs
    meta["input_hashes"] = input_hashes

    doc = {
        "meta": meta,
        "links": {
            "ops_vocab": path_utils.to_repo_relative(OPS_VOCAB, repo_root=ROOT),
            "ops_coverage": path_utils.to_repo_relative(OPS_COVERAGE, repo_root=ROOT),
            "tag_layouts": path_utils.to_repo_relative(TAG_LAYOUTS, repo_root=ROOT),
            "system_profile_digests": path_utils.to_repo_relative(SYSTEM_DIGESTS, repo_root=ROOT),
            "runtime_signatures": path_utils.to_repo_relative(RUNTIME_SIGNATURES, repo_root=ROOT),
            "op_runtime_summary": path_utils.to_repo_relative(OP_SUMMARY, repo_root=ROOT),
            "runtime_callout_oracle": path_utils.to_repo_relative(ORACLE, repo_root=ROOT),
        },
        "packets": packet_index,
        "profiles": {k: profiles[k] for k in sorted(profiles)},
        "expectations": {k: expectations[k] for k in sorted(expectations)},
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=2))
    print(f"[+] wrote {OUT}")
    return OUT


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate runtime_links.json from promotion packets.")
    parser.add_argument("--packets", type=Path, action="append", help="Promotion packet paths")
    args = parser.parse_args()
    generate(packet_paths=args.packets)


if __name__ == "__main__":
    main()
