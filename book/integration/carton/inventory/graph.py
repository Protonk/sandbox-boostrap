"""Build the CARTON inventory graph (tools/api/evidence/mappings/tests)."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from book.api import path_utils
from book.api import world as world_mod
from book.integration.carton import spec as spec_mod


SCHEMA_VERSION = "carton.inventory_graph.v0.1"

DEFAULT_OUT_PATH = Path(
    "book/integration/carton/bundle/relationships/inventory/inventory_graph.json"
)

_IGNORED_DIRS = {
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".venv",
    "__pycache__",
    ".module-cache",
    ".swiftpm",
    ".build",
}

_IGNORED_FILENAMES = {
    "readme.md",
    "notes.md",
    "plan.md",
}

_IGNORED_EXTS = {
    ".pyc",
    ".pyo",
    ".o",
    ".a",
    ".dylib",
    ".so",
    ".tmp",
}

_PATH_RE = re.compile(r"book/[A-Za-z0-9_./\\-]+")


@dataclass(frozen=True)
class InventoryArtifact:
    artifact_id: str
    path: str
    kind: str
    sensitivity: str
    digest_mode: str
    role: Optional[str] = None


@dataclass(frozen=True)
class InventoryEdge:
    source: str
    target: str
    kind: str


def _repo_root(repo_root: Optional[Path] = None) -> Path:
    return repo_root or path_utils.find_repo_root(Path(__file__))


def _to_rel(path: Path, repo_root: Path) -> str:
    return str(path_utils.to_repo_relative(path, repo_root=repo_root))


def _digest_mode(path: Path) -> str:
    if path.suffix.lower() == ".json":
        return "semantic_json"
    return "bytes"


def _artifact_id(kind: str, rel_path: str) -> str:
    return f"{kind}:{rel_path}"


def _is_ignored_filename(name: str) -> bool:
    return name.lower() in _IGNORED_FILENAMES


def _iter_files(root: Path, *, repo_root: Path, exclude_prefixes: Sequence[str]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dir_path = Path(dirpath)
        rel_dir = _to_rel(dir_path, repo_root)
        if any(rel_dir == prefix or rel_dir.startswith(prefix + "/") for prefix in exclude_prefixes):
            dirnames[:] = []
            continue
        dirnames[:] = [
            name
            for name in dirnames
            if name not in _IGNORED_DIRS and not name.startswith(".")
        ]
        for filename in filenames:
            if filename.startswith("."):
                continue
            if filename.lower().endswith(tuple(_IGNORED_EXTS)):
                continue
            yield dir_path / filename


def _classify_kind(rel_path: str) -> Optional[str]:
    if rel_path.startswith("book/tools/"):
        return "tool"
    if rel_path.startswith("book/api/"):
        return "api"
    if rel_path.startswith("book/evidence/"):
        return "evidence"
    if rel_path.startswith("book/integration/tests/"):
        return "test"
    if rel_path.startswith("book/integration/carton/bundle/"):
        return "mapping"
    if rel_path.startswith("book/integration/carton/spec/"):
        return "contract"
    if rel_path.startswith("book/integration/carton/schemas/"):
        return "contract"
    return None


def _should_track(rel_path: str, *, kind: str, is_contract: bool) -> bool:
    name = Path(rel_path).name
    if not is_contract and _is_ignored_filename(name):
        return False
    if kind in {"tool", "api"} and not is_contract:
        if Path(rel_path).suffix.lower() in {".md", ".rst"}:
            return False
    return True


def _extract_paths(text: str) -> List[str]:
    return [match.strip().rstrip(").,") for match in _PATH_RE.findall(text or "")]


def _expand_braces(pattern: str) -> List[str]:
    if "{" not in pattern or "}" not in pattern:
        return [pattern]
    prefix, rest = pattern.split("{", 1)
    inner, suffix = rest.split("}", 1)
    parts = [part.strip() for part in inner.split(",") if part.strip()]
    return [f"{prefix}{part}{suffix}" for part in parts]


def _load_owners_guardrails(repo_root: Path) -> List[Tuple[List[str], List[str]]]:
    owners_path = repo_root / "book/integration/carton/mappings/OWNERS.md"
    if not owners_path.exists():
        return []
    rows: List[Tuple[List[str], List[str]]] = []
    for line in owners_path.read_text().splitlines():
        if not line.startswith("|"):
            continue
        parts = [part.strip() for part in line.strip().split("|")[1:-1]]
        if len(parts) != 4 or parts[0] == "Artifact(s)":
            continue
        artifacts_raw = parts[0]
        guard_raw = parts[3]
        artifacts: List[str] = []
        for path in _extract_paths(artifacts_raw):
            artifacts.extend(_expand_braces(path))
        guardrails = [p for p in _extract_paths(guard_raw) if p.endswith(".py")]
        if artifacts and guardrails:
            rows.append((artifacts, guardrails))
    return rows


def _match_guardrails(artifact_path: str, owner_rows: List[Tuple[List[str], List[str]]]) -> List[str]:
    matches: List[str] = []
    for patterns, guardrails in owner_rows:
        for pattern in patterns:
            if fnmatch.fnmatch(artifact_path, pattern):
                matches.extend(guardrails)
                break
    return matches


def build_inventory_graph(
    repo_root: Optional[Path] = None,
    *,
    include_experiments: bool = False,
) -> Dict[str, Any]:
    repo_root = _repo_root(repo_root)
    world_data, resolution = world_mod.load_world(repo_root=repo_root)
    world_id = world_mod.require_world_id(world_data, world_path=resolution.entry.world_path)

    exclude_prefixes = [
        "book/integration/out",
        "book/integration/carton/graph/.module-cache",
    ]
    evidence_excludes = [
        "book/evidence/dumps",
    ]
    if not include_experiments:
        evidence_excludes.append("book/evidence/experiments")

    artifacts: Dict[str, InventoryArtifact] = {}
    edges: Set[Tuple[str, str, str]] = set()

    # Scan tools/api/evidence roots (excluding experiments by default).
    scan_roots = [
        repo_root / "book/tools",
        repo_root / "book/api",
        repo_root / "book/evidence",
    ]
    for root in scan_roots:
        if not root.exists():
            continue
        excludes = exclude_prefixes[:]
        if root.name == "evidence":
            excludes.extend(evidence_excludes)
        for path in _iter_files(root, repo_root=repo_root, exclude_prefixes=excludes):
            rel_path = _to_rel(path, repo_root)
            kind = _classify_kind(rel_path) or "evidence"
            is_contract = spec_mod.is_contract_path(rel_path)
            if not _should_track(rel_path, kind=kind, is_contract=is_contract):
                continue
            sensitivity = "contract" if is_contract else "normal"
            artifact_id = _artifact_id(kind, rel_path)
            artifacts[artifact_id] = InventoryArtifact(
                artifact_id=artifact_id,
                path=rel_path,
                kind=kind,
                sensitivity=sensitivity,
                digest_mode=_digest_mode(path),
            )

    # Include explicit contract paths elsewhere in the repo.
    for path in _iter_files(repo_root, repo_root=repo_root, exclude_prefixes=exclude_prefixes):
        rel_path = _to_rel(path, repo_root)
        if rel_path.startswith("book/evidence/experiments") and not include_experiments:
            continue
        if not spec_mod.is_contract_path(rel_path):
            continue
        kind = _classify_kind(rel_path) or "contract"
        artifact_id = _artifact_id(kind, rel_path)
        existing = artifacts.get(artifact_id)
        if existing:
            artifacts[artifact_id] = InventoryArtifact(
                artifact_id=existing.artifact_id,
                path=existing.path,
                kind=existing.kind,
                sensitivity="contract",
                digest_mode=existing.digest_mode,
                role=existing.role,
            )
        else:
            artifacts[artifact_id] = InventoryArtifact(
                artifact_id=artifact_id,
                path=rel_path,
                kind=kind,
                sensitivity="contract",
                digest_mode=_digest_mode(path),
            )

    # Gather registry artifacts + job inputs for evidence and mapping edges.
    from book.integration.carton.core import registry as registry_mod

    registry = registry_mod.build_registry()
    mapping_paths = {
        art.path for art in registry.artifacts if art.path.startswith("book/integration/carton/bundle/")
    }
    for art in registry.artifacts:
        if art.path not in mapping_paths:
            continue
        artifact_id = _artifact_id("mapping", art.path)
        artifacts[artifact_id] = InventoryArtifact(
            artifact_id=artifact_id,
            path=art.path,
            kind="mapping",
            sensitivity="normal",
            digest_mode=art.hash_mode,
            role=art.role,
        )

    # Evidence -> mapping edges from registry job inputs.
    for job in registry.jobs:
        outputs = job.outputs
        mapping_outputs = [path for path in outputs if path in mapping_paths]
        if not mapping_outputs:
            continue
        for input_path in job.inputs:
            if not input_path.startswith("book/evidence/"):
                continue
            evidence_id = _artifact_id("evidence", input_path)
            if evidence_id not in artifacts:
                artifacts[evidence_id] = InventoryArtifact(
                    artifact_id=evidence_id,
                    path=input_path,
                    kind="evidence",
                    sensitivity="normal",
                    digest_mode=_digest_mode(path_utils.ensure_absolute(input_path, repo_root=repo_root)),
                )
            for out_path in mapping_outputs:
                edges.add((evidence_id, _artifact_id("mapping", out_path), "consumes"))

    # Mapping -> test edges from OWNERS guardrails.
    owners_rows = _load_owners_guardrails(repo_root)
    for mapping_path in sorted(mapping_paths):
        guardrails = _match_guardrails(mapping_path, owners_rows)
        if not guardrails:
            continue
        mapping_id = _artifact_id("mapping", mapping_path)
        for test_path in guardrails:
            test_id = _artifact_id("test", test_path)
            if test_id not in artifacts:
                artifacts[test_id] = InventoryArtifact(
                    artifact_id=test_id,
                    path=test_path,
                    kind="test",
                    sensitivity="normal",
                    digest_mode="bytes",
                )
            edges.add((mapping_id, test_id, "guards"))

    metadata_inputs = [
        "book/integration/carton/mappings/OWNERS.md",
        "book/integration/carton/core/registry.py",
        "book/integration/carton/inventory/graph.py",
    ]

    artifact_list = sorted(artifacts.values(), key=lambda a: a.artifact_id)
    edge_list = sorted(edges, key=lambda e: (e[0], e[1], e[2]))

    return {
        "schema_version": SCHEMA_VERSION,
        "world_id": world_id,
        "metadata": {
            "world_id": world_id,
            "generated_by": "book/integration/carton/inventory/generate_inventory_graph.py",
            "inputs": metadata_inputs,
        },
        "artifacts": [
            {
                "id": art.artifact_id,
                "path": art.path,
                "kind": art.kind,
                "sensitivity": art.sensitivity,
                "digest_mode": art.digest_mode,
                **({"role": art.role} if art.role else {}),
            }
            for art in artifact_list
        ],
        "edges": [
            {"from": src, "to": dst, "kind": kind} for src, dst, kind in edge_list
        ],
    }


def load_inventory_graph(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing inventory graph: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_digest(doc: Dict[str, Any]) -> str:
    payload = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
