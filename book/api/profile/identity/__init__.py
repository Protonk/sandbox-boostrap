"""
Profile identity resolution helpers (Sonoma baseline).
"""

from __future__ import annotations

from .api import (  # noqa: F401
    BASELINE_REF,
    SYSTEM_ATTESTATIONS_REF,
    SYSTEM_DIGESTS_REF,
    SYSTEM_STATIC_CHECKS_REF,
    CanonicalSystemProfileIdentity,
    IdentityDataError,
    IdentityMismatchError,
    ProfileIdentityError,
    UnknownProfileError,
    baseline_world_id,
    canonical_system_profile_ids,
    resolve_all_canonical_system_profiles,
    resolve_canonical_system_profile,
)

__all__ = [
    "ProfileIdentityError",
    "UnknownProfileError",
    "IdentityDataError",
    "IdentityMismatchError",
    "CanonicalSystemProfileIdentity",
    "BASELINE_REF",
    "SYSTEM_DIGESTS_REF",
    "SYSTEM_STATIC_CHECKS_REF",
    "SYSTEM_ATTESTATIONS_REF",
    "baseline_world_id",
    "canonical_system_profile_ids",
    "resolve_canonical_system_profile",
    "resolve_all_canonical_system_profiles",
]

