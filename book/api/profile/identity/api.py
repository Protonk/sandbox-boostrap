"""
Profile identity resolution helpers for the Sonoma Seatbelt baseline.

The repo has multiple, intentionally different identity surfaces for profiles:
- Canonical system profile ids: `sys:airlock`, `sys:bsd`, `sys:sample`
- Compiled blob repo-relative paths: `book/graph/concepts/validation/fixtures/blobs/*.sb.bin`
- Compiled blob sha256 digests (contract + witnesses)
- Per-blob attestations and static checks keyed by blob path

This module provides a small resolver that joins these surfaces mechanically,
using the compiled-blob path and sha256 as the primary join keys.

Public API is re-exported from `book.api.profile.identity`.

This is intentionally *not* a policy-semantic identity:
- It does not attempt to interpret what a profile “means”.
- It only reconciles mapping records that are already world-scoped and
  manifest-verified elsewhere.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from book.api.path_utils import find_repo_root, to_repo_relative

BASELINE_REF = Path("book/world/sonoma-14.4.1-23E224-arm64/world.json")
SYSTEM_DIGESTS_REF = Path("book/graph/mappings/system_profiles/digests.json")
SYSTEM_STATIC_CHECKS_REF = Path("book/graph/mappings/system_profiles/static_checks.json")
SYSTEM_ATTESTATIONS_REF = Path("book/graph/mappings/system_profiles/attestations.json")


class ProfileIdentityError(Exception):
    """Base error for identity resolution failures."""


class UnknownProfileError(ProfileIdentityError):
    """Raised when a profile id is not present in the relevant mapping."""


class IdentityDataError(ProfileIdentityError):
    """Raised when a required mapping file is missing or malformed."""


class IdentityMismatchError(ProfileIdentityError):
    """Raised when different mappings disagree about the same blob."""


@dataclass(frozen=True)
class CanonicalSystemProfileIdentity:
    """
    Joined view of one canonical system profile across mappings.

    `blob_path` is always repo-relative. `blob_sha256` is the contract sha256
    from system profile digests.
    """

    profile_id: str
    blob_path: str
    blob_sha256: str
    digests_entry: Dict[str, Any]
    static_checks_entry: Dict[str, Any]
    attestation_entry: Dict[str, Any]


def _load_json(path: Path) -> Dict[str, Any]:
    """Load JSON and raise identity-specific exceptions for common failure modes."""
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise IdentityDataError(f"missing mapping: {path}") from exc
    except json.JSONDecodeError as exc:
        raise IdentityDataError(f"malformed JSON mapping: {path}") from exc


def baseline_world_id(repo_root: Optional[Path] = None) -> str:
    """
    Return the baseline `world_id` for the current checkout.

    This is the single source of truth for host scoping.
    """
    root = repo_root or find_repo_root(Path(__file__))
    data = _load_json(root / BASELINE_REF)
    world_id = data.get("world_id")
    if not world_id:
        raise IdentityDataError(f"baseline missing world_id: {to_repo_relative(root / BASELINE_REF, root)}")
    return str(world_id)


def canonical_system_profile_ids(repo_root: Optional[Path] = None) -> Sequence[str]:
    """List canonical system profile ids from `system_profiles/digests.json`."""
    root = repo_root or find_repo_root(Path(__file__))
    digests = _load_json(root / SYSTEM_DIGESTS_REF)
    meta = digests.get("metadata") or {}
    canonical = meta.get("canonical_profiles") or {}
    return list(sorted(canonical.keys()))


def _index_static_checks(static_checks: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Index static-check entries by `path` (repo-relative)."""
    entries = static_checks.get("entries") or []
    by_path: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        if isinstance(path, str):
            by_path[path] = entry
    return by_path


def _index_attestations(attestations: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Index attestation entries by `source` (repo-relative blob path)."""
    entries = attestations.get("attestations") or []
    by_source: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        source = entry.get("source")
        if isinstance(source, str):
            by_source[source] = entry
    return by_source


def resolve_canonical_system_profile(
    profile_id: str,
    *,
    repo_root: Optional[Path] = None,
    require_world_match: bool = True,
    require_sha_match: bool = True,
) -> CanonicalSystemProfileIdentity:
    """
    Resolve one `sys:<name>` canonical system profile into a joined identity.

    Args:
        profile_id: Canonical id (e.g. `sys:bsd`).
        repo_root: Optional repo root for callers running outside the checkout.
        require_world_match: If true, ensure all involved mappings share the same
            `world_id` as `book/world/.../world.json`.
        require_sha_match: If true, ensure sha256 values agree across mappings.

    Returns:
        A `CanonicalSystemProfileIdentity` containing the original per-mapping
        entries as well as the join keys (`blob_path`, `blob_sha256`).
    """
    root = repo_root or find_repo_root(Path(__file__))
    digests = _load_json(root / SYSTEM_DIGESTS_REF)
    static_checks = _load_json(root / SYSTEM_STATIC_CHECKS_REF)
    attestations = _load_json(root / SYSTEM_ATTESTATIONS_REF)

    if require_world_match:
        # World scoping is non-negotiable in this repo. If these drift, callers
        # must treat the situation as “mixed baselines” and stop.
        world_id = baseline_world_id(root)
        for label, doc in [
            ("system_profiles/digests.json", digests),
            ("system_profiles/static_checks.json", static_checks),
            ("system_profiles/attestations.json", attestations),
        ]:
            doc_world = (doc.get("metadata") or {}).get("world_id")
            if doc_world != world_id:
                raise IdentityMismatchError(f"world_id mismatch for {label}: expected {world_id}, got {doc_world}")

    profiles = digests.get("profiles") or {}
    if profile_id not in profiles:
        raise UnknownProfileError(f"unknown canonical system profile id: {profile_id}")
    digest_entry = profiles[profile_id] or {}

    blob_path = digest_entry.get("source")
    if not isinstance(blob_path, str) or not blob_path:
        raise IdentityDataError(f"{SYSTEM_DIGESTS_REF} entry missing source for {profile_id}")

    contract = digest_entry.get("contract") or {}
    blob_sha256 = contract.get("blob_sha256")
    if not isinstance(blob_sha256, str) or not blob_sha256:
        raise IdentityDataError(f"{SYSTEM_DIGESTS_REF} entry missing contract.blob_sha256 for {profile_id}")

    static_by_path = _index_static_checks(static_checks)
    static_entry = static_by_path.get(blob_path)
    if not static_entry:
        raise IdentityDataError(f"static checks missing entry for blob path {blob_path} ({profile_id})")

    att_by_source = _index_attestations(attestations)
    attest_entry = att_by_source.get(blob_path)
    if not attest_entry:
        raise IdentityDataError(f"attestations missing entry for blob path {blob_path} ({profile_id})")

    if require_sha_match:
        static_sha = static_entry.get("sha256")
        if static_sha != blob_sha256:
            raise IdentityMismatchError(
                f"sha256 mismatch for {profile_id}: digests contract {blob_sha256} vs static_checks {static_sha}"
            )
        attest_sha = attest_entry.get("sha256")
        if attest_sha != blob_sha256:
            raise IdentityMismatchError(
                f"sha256 mismatch for {profile_id}: digests contract {blob_sha256} vs attestations {attest_sha}"
            )

    canonical_in_attestation = attest_entry.get("canonical_profile_id")
    if canonical_in_attestation is not None and canonical_in_attestation != profile_id:
        raise IdentityMismatchError(
            f"attestation canonical_profile_id mismatch for {profile_id}: {canonical_in_attestation}"
        )

    return CanonicalSystemProfileIdentity(
        profile_id=profile_id,
        blob_path=blob_path,
        blob_sha256=blob_sha256,
        digests_entry=digest_entry,
        static_checks_entry=static_entry,
        attestation_entry=attest_entry,
    )


def resolve_all_canonical_system_profiles(
    *,
    repo_root: Optional[Path] = None,
    require_world_match: bool = True,
    require_sha_match: bool = True,
) -> Dict[str, CanonicalSystemProfileIdentity]:
    """
    Resolve all canonical system profiles into joined identities.

    This is a convenience wrapper around `resolve_canonical_system_profile` that
    preserves the canonical ids as keys.
    """
    root = repo_root or find_repo_root(Path(__file__))
    out: Dict[str, CanonicalSystemProfileIdentity] = {}
    for pid in canonical_system_profile_ids(root):
        out[pid] = resolve_canonical_system_profile(
            pid,
            repo_root=root,
            require_world_match=require_world_match,
            require_sha_match=require_sha_match,
        )
    return out
