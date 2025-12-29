"""
Runtime plan builder (template -> plan/registry artifacts).

This module centralizes template-driven plan generation so experiments can stay
data-only and reuse consistent expected-matrix logic.

Templates are a quick-start for new probe families. They keep the
plan/registry shapes consistent across experiments.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from book.api import path_utils
from book.api.runtime.plans import loader as runtime_plan
from book.api.runtime.plans import registry as runtime_registry
from book.api.runtime.contracts import models


REPO_ROOT = path_utils.find_repo_root(Path(__file__))

TEMPLATE_SCHEMA_VERSION = "runtime-tools.plan_template.v0.1"
# Hardcoded template index keeps template resolution deterministic.
TEMPLATE_INDEX: Dict[str, Path] = {
    "runtime-adversarial": REPO_ROOT
    / "book"
    / "api"
    / "runtime"
    / "plans"
    / "templates"
    / "runtime_adversarial.json",
    "vfs-canonicalization": REPO_ROOT
    / "book"
    / "api"
    / "runtime"
    / "plans"
    / "templates"
    / "vfs_canonicalization.json",
}


@dataclass(frozen=True)
class PlanBuildResult:
    template_id: str
    registry_id: str
    plan_path: Path
    probes_path: Path
    profiles_path: Path
    expected_matrix_path: Optional[Path]


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _write_json(path: Path, payload: Dict[str, Any], *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def _require_schema(doc: Dict[str, Any], *, expected: str, label: str) -> None:
    schema = doc.get("schema_version")
    if schema != expected:
        raise ValueError(f"{label} schema mismatch: {schema!r} != {expected!r}")


def _build_static_template(
    template: Dict[str, Any],
    out_root: Path,
    *,
    overwrite: bool,
    write_expected_matrix: bool,
) -> PlanBuildResult:
    plan_doc = template.get("plan")
    probes_doc = template.get("probes")
    profiles_doc = template.get("profiles")
    if not isinstance(plan_doc, dict) or not isinstance(probes_doc, dict) or not isinstance(profiles_doc, dict):
        raise ValueError("static templates must include plan/probes/profiles objects")

    _require_schema(plan_doc, expected=runtime_plan.PLAN_SCHEMA_VERSION, label="plan")
    _require_schema(probes_doc, expected=runtime_registry.PROBE_SCHEMA_VERSION, label="probes")
    _require_schema(profiles_doc, expected=runtime_registry.PROFILE_SCHEMA_VERSION, label="profiles")

    registry_id = template.get("registry_id") or plan_doc.get("registry_id")
    if registry_id is None:
        raise ValueError("static template missing registry_id")
    for doc, label in [(plan_doc, "plan"), (probes_doc, "probes"), (profiles_doc, "profiles")]:
        if doc.get("registry_id") != registry_id:
            raise ValueError(f"{label} registry_id mismatch: {doc.get('registry_id')} != {registry_id}")

    plan_path = out_root / "plan.json"
    registry_dir = out_root / "registry"
    probes_path = registry_dir / "probes.json"
    profiles_path = registry_dir / "profiles.json"
    _write_json(plan_path, plan_doc, overwrite=overwrite)
    _write_json(probes_path, probes_doc, overwrite=overwrite)
    _write_json(profiles_path, profiles_doc, overwrite=overwrite)

    expected_matrix_path: Optional[Path] = None
    if write_expected_matrix and isinstance(template.get("expected_matrix"), dict):
        expected_matrix_path = out_root / "out" / "expected_matrix.json"
        expected_matrix_path.parent.mkdir(parents=True, exist_ok=True)
        expected_matrix_path.write_text(json.dumps(template["expected_matrix"], indent=2))

    return PlanBuildResult(
        template_id=template.get("template_id") or registry_id,
        registry_id=registry_id,
        plan_path=plan_path,
        probes_path=probes_path,
        profiles_path=profiles_path,
        expected_matrix_path=expected_matrix_path,
    )


def list_plan_templates() -> List[Dict[str, Any]]:
    """List available plan templates with descriptions and paths."""
    templates: List[Dict[str, Any]] = []
    for template_id, path in TEMPLATE_INDEX.items():
        if not path.exists():
            continue
        doc = _load_json(path)
        templates.append(
            {
                "template_id": template_id,
                "description": doc.get("description"),
                "path": str(path_utils.to_repo_relative(path, repo_root=REPO_ROOT)),
            }
        )
    return templates


def load_plan_template(template_id: str) -> Dict[str, Any]:
    """Load a plan template by id and validate its schema."""
    path = TEMPLATE_INDEX.get(template_id)
    if not path:
        raise KeyError(f"unknown template id: {template_id}")
    doc = _load_json(path)
    if doc.get("schema_version") != TEMPLATE_SCHEMA_VERSION:
        raise ValueError(f"template schema mismatch: {doc.get('schema_version')}")
    if doc.get("template_id") and doc.get("template_id") != template_id:
        raise ValueError(f"template id mismatch: {doc.get('template_id')} != {template_id}")
    return doc


def _resolve_path_list(value: Any, path_sets: Dict[str, Any], *, field: str) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        if value in path_sets:
            value = path_sets[value]
        else:
            return [value]
    if not isinstance(value, list):
        raise TypeError(f"{field} must be a list or path_set ref")
    if value and isinstance(value[0], list):
        raise TypeError(f"{field} expected list of strings, got list of lists")
    return [str(v) for v in value]


def _resolve_path_pairs(value: Any, path_sets: Dict[str, Any], *, field: str) -> List[Tuple[str, str]]:
    if isinstance(value, str):
        value = path_sets.get(value)
    if not value:
        return []
    if not isinstance(value, list):
        raise TypeError(f"{field} must be a list of pairs or path_set ref")
    pairs: List[Tuple[str, str]] = []
    for pair in value:
        if not isinstance(pair, list) or len(pair) != 2:
            raise TypeError(f"{field} entries must be 2-item lists, got {pair!r}")
        pairs.append((str(pair[0]), str(pair[1])))
    return pairs


def _expected_decisions(policy: str, role: str, primary_path: str, alternate_path: str) -> Tuple[str, str]:
    if policy == "literal":
        if role == "first_only":
            return "allow", "deny"
        if role == "second_only":
            return "deny", "allow"
        if role == "both":
            return "allow", "allow"
        raise ValueError(f"unknown role {role}")

    if policy in {"canonicalized", "canonicalized_with_var_tmp_exception"}:
        if role == "first_only":
            primary = "deny"
            alternate = "deny"
        elif role in {"second_only", "both"}:
            primary = "allow"
            alternate = "allow"
        else:
            raise ValueError(f"unknown role {role}")

        if policy == "canonicalized_with_var_tmp_exception" and alternate_path.startswith("/private/var/"):
            primary = "deny"
            if role == "first_only":
                alternate = "deny"
            else:
                alternate = "allow"
        return primary, alternate

    raise ValueError(f"unknown policy {policy}")


def build_expected_entries(template: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Expand template path policies into expected decision rows."""
    path_sets = template.get("path_sets") or {}
    profiles = template.get("profiles") or {}
    profile_order: Sequence[str] = template.get("profile_order") or list(profiles.keys())

    entries: List[Dict[str, Any]] = []
    for profile_id in profile_order:
        cfg = profiles.get(profile_id) or {}
        ops = cfg.get("ops") or []
        policy = cfg.get("policy")
        variant = cfg.get("variant")

        if policy == "literal":
            request_paths = _resolve_path_list(cfg.get("request_paths"), path_sets, field="request_paths")
            allowed_paths = set(_resolve_path_list(cfg.get("allowed_paths"), path_sets, field="allowed_paths"))
            for path in request_paths:
                expected = "allow" if path in allowed_paths else "deny"
                for op in ops:
                    note_bits = [profile_id, f"{variant}/{policy}" if variant else policy, path]
                    entries.append(
                        {
                            "profile_id": profile_id,
                            "operation": op,
                            "requested_path": path,
                            "expected_decision": expected,
                            "notes": " ".join(bit for bit in note_bits if bit),
                        }
                    )
            continue

        role = cfg.get("role")
        pairs = _resolve_path_pairs(cfg.get("path_pairs"), path_sets, field="path_pairs")
        for primary_path, alternate_path in pairs:
            primary_expected, alternate_expected = _expected_decisions(policy, role, primary_path, alternate_path)
            for op in ops:
                note_bits = [profile_id, f"{variant}/{policy}/{role}" if variant else f"{policy}/{role}"]
                entries.append(
                    {
                        "profile_id": profile_id,
                        "operation": op,
                        "requested_path": primary_path,
                        "expected_decision": primary_expected,
                        "notes": " ".join(bit for bit in note_bits if bit) + f" primary {primary_path}",
                    }
                )
                entries.append(
                    {
                        "profile_id": profile_id,
                        "operation": op,
                        "requested_path": alternate_path,
                        "expected_decision": alternate_expected,
                        "notes": " ".join(bit for bit in note_bits if bit) + f" alternate {alternate_path}",
                    }
                )
    return entries


def collect_anchor_paths(template: Dict[str, Any]) -> List[str]:
    """Return sorted anchor paths referenced by the template expectations."""
    anchors = {entry["requested_path"] for entry in build_expected_entries(template)}
    return sorted(anchors)


def _probe_name(operation: str, target: str) -> str:
    if operation == "file-read*":
        prefix = "read"
    elif operation == "file-write*":
        prefix = "write"
    else:
        prefix = operation.replace("*", "")
    return f"{prefix}_{target}"


def _build_vfs(template: Dict[str, Any], out_root: Path, *, overwrite: bool, write_expected_matrix: bool) -> PlanBuildResult:
    registry_id = template.get("registry_id") or template.get("template_id") or "vfs-canonicalization"
    world_id = template.get("world_id") or models.WORLD_ID
    plan_id = template.get("plan_id") or f"{registry_id}.v1"

    profiles_cfg = template.get("profiles") or {}
    profile_order: Sequence[str] = template.get("profile_order") or list(profiles_cfg.keys())

    expected_entries = build_expected_entries(template)
    probes: Dict[str, Dict[str, Any]] = {}
    profile_probe_refs: Dict[str, List[str]] = {pid: [] for pid in profile_order}
    for entry in expected_entries:
        profile_id = entry["profile_id"]
        op = entry["operation"]
        path = entry["requested_path"]
        name = _probe_name(op, path)
        probe_id = f"{profile_id}:{name}"
        probe = {
            "probe_id": probe_id,
            "name": name,
            "operation": op,
            "target": path,
            "expected": entry["expected_decision"],
        }
        if probe_id in probes:
            if probes[probe_id].get("expected") != probe["expected"]:
                raise ValueError(f"probe expectation mismatch: {probe_id}")
        else:
            probes[probe_id] = probe
        if probe_id not in profile_probe_refs.setdefault(profile_id, []):
            profile_probe_refs[profile_id].append(probe_id)

    family = template.get("family")
    semantic_group = template.get("semantic_group")
    profiles: Dict[str, Dict[str, Any]] = {}
    for profile_id in profile_order:
        cfg = profiles_cfg.get(profile_id) or {}
        sbpl_path = cfg.get("sbpl")
        if not sbpl_path:
            raise ValueError(f"profile missing sbpl path: {profile_id}")
        abs_path = path_utils.ensure_absolute(Path(sbpl_path), REPO_ROOT)
        profiles[profile_id] = {
            "profile_id": profile_id,
            "profile_path": path_utils.to_repo_relative(abs_path, repo_root=REPO_ROOT),
            "mode": "sbpl",
            "family": cfg.get("family") or family,
            "semantic_group": cfg.get("semantic_group") or semantic_group,
            "probe_refs": profile_probe_refs.get(profile_id) or [],
            "notes": cfg.get("notes"),
        }

    plan_doc: Dict[str, Any] = {
        "schema_version": runtime_plan.PLAN_SCHEMA_VERSION,
        "plan_id": plan_id,
        "registry_id": registry_id,
        "world_id": world_id,
        "profiles": list(profile_order),
        "lanes": template.get("lanes") or {"baseline": True, "scenario": True, "oracle": True},
        "controls": template.get("controls") or {"baseline": True},
    }
    if template.get("apply_preflight_profile"):
        plan_doc["apply_preflight_profile"] = template.get("apply_preflight_profile")

    registry_dir = out_root / "registry"
    probes_doc = {
        "schema_version": runtime_registry.PROBE_SCHEMA_VERSION,
        "registry_id": registry_id,
        "world_id": world_id,
        "probes": probes,
    }
    profiles_doc = {
        "schema_version": runtime_registry.PROFILE_SCHEMA_VERSION,
        "registry_id": registry_id,
        "world_id": world_id,
        "profiles": profiles,
    }

    plan_path = out_root / "plan.json"
    probes_path = registry_dir / "probes.json"
    profiles_path = registry_dir / "profiles.json"
    _write_json(plan_path, plan_doc, overwrite=overwrite)
    _write_json(probes_path, probes_doc, overwrite=overwrite)
    _write_json(profiles_path, profiles_doc, overwrite=overwrite)

    expected_matrix_path: Optional[Path] = None
    if write_expected_matrix:
        expected_matrix_path = out_root / "out" / "expected_matrix.json"
        expected_matrix_path.parent.mkdir(parents=True, exist_ok=True)
        expected_matrix_path.write_text(json.dumps(expected_entries, indent=2))

    return PlanBuildResult(
        template_id=template.get("template_id") or "vfs-canonicalization",
        registry_id=registry_id,
        plan_path=plan_path,
        probes_path=probes_path,
        profiles_path=profiles_path,
        expected_matrix_path=expected_matrix_path,
    )


def build_plan_from_template(
    template_id: str,
    out_root: Path,
    *,
    repo_root: Optional[Path] = None,
    overwrite: bool = False,
    write_expected_matrix: bool = True,
) -> PlanBuildResult:
    """Render a template into plan/registry files under out_root."""
    template = load_plan_template(template_id)
    out_root = path_utils.ensure_absolute(out_root, repo_root or REPO_ROOT)
    if template_id == "vfs-canonicalization":
        return _build_vfs(template, out_root, overwrite=overwrite, write_expected_matrix=write_expected_matrix)
    if template_id == "runtime-adversarial":
        return _build_static_template(template, out_root, overwrite=overwrite, write_expected_matrix=write_expected_matrix)
    raise ValueError(f"no builder registered for template: {template_id}")
