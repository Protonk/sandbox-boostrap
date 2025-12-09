"""
Generate promoted golden artifacts from runtime-checks outputs.

This is the consolidated home for the former `runtime_golden.generate`.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List

from book.api import decoder
from book.api.profile_tools import compile as compile_mod

# Golden profile keys (runtime-checks).
GOLDEN_KEYS = [
    "bucket4:v1_read",
    "bucket5:v11_read_subpath",
    "runtime:metafilter_any",
    "runtime:strict_1",
    "sys:bsd",
    "sys:airlock",
]


@dataclass
class GoldenProfile:
    key: str
    path: Path
    mode: str

    @property
    def is_blob(self) -> bool:
        return self.path.suffix == ".bin"


@dataclass
class BaselineInfo:
    world_id: str
    baseline_ref: str


def load_baseline(baseline_ref: str) -> BaselineInfo:
    path = Path(baseline_ref)
    data = json.loads(path.read_text())
    world_id = data.get("world_id")
    if not world_id:
        raise ValueError(f"world_id missing from baseline {baseline_ref}")
    return BaselineInfo(world_id=world_id, baseline_ref=baseline_ref)


def load_matrix(matrix_path: Path) -> Dict[str, GoldenProfile]:
    data = json.loads(matrix_path.read_text())
    profiles = data.get("profiles") or {}
    out: Dict[str, GoldenProfile] = {}
    for key in GOLDEN_KEYS:
        rec = profiles.get(key)
        if not rec:
            raise ValueError(f"missing profile {key} in expected_matrix.json")
        out[key] = GoldenProfile(
            key=key,
            path=Path(rec["blob"]),
            mode=rec.get("mode", "sbpl"),
        )
    return out


def sha256_bytes(buf: bytes) -> str:
    return hashlib.sha256(buf).hexdigest()


def compile_profile(profile: GoldenProfile) -> bytes:
    if profile.is_blob:
        return profile.path.read_bytes()
    return compile_mod.compile_sbpl_string(profile.path.read_text()).blob


def decode_profile(blob: bytes) -> Dict[str, Any]:
    return decoder.decode_profile_dict(blob)


def summarize_decode(key: str, blob_path: Path, blob_bytes: bytes, decoded: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "key": key,
        "blob": str(blob_path),
        "sha256": sha256_bytes(blob_bytes),
        "node_count": decoded.get("node_count"),
        "op_count": decoded.get("op_count"),
        "tag_counts": decoded.get("tag_counts"),
        "literal_strings": decoded.get("literal_strings"),
    }


def normalize_runtime_results(runtime_results: Path, profiles: Iterable[str]) -> List[Dict[str, Any]]:
    data = json.loads(runtime_results.read_text())
    rows: List[Dict[str, Any]] = []
    for key in profiles:
        entry = data.get(key) or {}
        for probe in entry.get("probes") or []:
            rows.append(
                {
                    "profile": key,
                    "probe": probe.get("name"),
                    "expected": probe.get("expected"),
                    "actual": probe.get("actual"),
                    "match": probe.get("match"),
                    "operation": probe.get("operation"),
                    "path": probe.get("path"),
                    "exit_code": probe.get("exit_code"),
                    "violation_summary": probe.get("violation_summary"),
                    "command": probe.get("command"),
                }
            )
    return rows


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
