"""
Shared probe plan for entitlement-diff runtime witnesses.

This module exists to keep probe IDs and argument vectors identical across
different runners (e.g., blob-applied SBPL-wrapper vs App Sandbox jail).

The plan is intentionally small and concrete:
- stage a fixed set of probe binaries into a runner-chosen stage directory
- run a fixed probe matrix against runner-chosen container paths
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence

from book.api.path_utils import find_repo_root


@dataclass(frozen=True)
class StagedBinarySpec:
    id: str
    src_path: Path
    dest_name: str


def _default_repo_root() -> Path:
    return find_repo_root(Path(__file__))


def staged_binary_specs(repo_root: Path | None = None) -> Sequence[StagedBinarySpec]:
    root = repo_root or _default_repo_root()
    return (
        StagedBinarySpec(
            id="entitlement_sample",
            src_path=root / "book" / "experiments" / "entitlement-diff" / "entitlement_sample",
            dest_name="entitlement_sample",
        ),
        StagedBinarySpec(
            id="entitlement_sample_unsigned",
            src_path=root / "book" / "experiments" / "entitlement-diff" / "entitlement_sample_unsigned",
            dest_name="entitlement_sample_unsigned",
        ),
        StagedBinarySpec(
            id="mach_probe",
            src_path=root / "book" / "experiments" / "runtime-checks" / "mach_probe",
            dest_name="mach_probe",
        ),
        StagedBinarySpec(
            id="file_probe",
            src_path=root / "book" / "api" / "runtime" / "native" / "file_probe" / "file_probe",
            dest_name="file_probe",
        ),
    )


def staged_destinations(stage_dir: Path, repo_root: Path | None = None) -> Dict[str, Path]:
    return {spec.id: stage_dir / spec.dest_name for spec in staged_binary_specs(repo_root)}


def file_probe_target(container_dir: Path) -> Path:
    return container_dir / "runtime.txt"


def probe_ids() -> List[str]:
    return [
        "network_bind",
        "network_outbound_localhost",
        "mach_lookup_cfprefsd_agent",
        "file_read",
        "file_write",
    ]


def build_probe_matrix(
    *,
    stage_dir: Path,
    container_dir: Path,
    network_bind_binary_id: str = "entitlement_sample",
    repo_root: Path | None = None,
) -> List[Dict[str, object]]:
    """
    Build the canonical probe matrix.

    Callers are responsible for staging binaries according to staged_binary_specs()
    into `stage_dir` before running the returned commands.
    """

    staged = staged_destinations(stage_dir, repo_root)
    if network_bind_binary_id not in staged:
        raise ValueError(f"unknown network_bind_binary_id: {network_bind_binary_id}")

    target = file_probe_target(container_dir)
    return [
        {"id": "network_bind", "command": [str(staged[network_bind_binary_id])]},
        {"id": "network_outbound_localhost", "command": ["/usr/bin/nc", "-z", "-w", "2", "127.0.0.1", "80"]},
        {"id": "mach_lookup_cfprefsd_agent", "command": [str(staged["mach_probe"]), "com.apple.cfprefsd.agent"]},
        {"id": "file_read", "command": [str(staged["file_probe"]), "read", str(target)]},
        {"id": "file_write", "command": [str(staged["file_probe"]), "write", str(target)]},
    ]
