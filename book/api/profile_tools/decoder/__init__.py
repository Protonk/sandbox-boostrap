"""
Best-effort structural decoder for compiled sandbox profile blobs (Sonoma baseline).

Public API:
- `decode_profile`, `decode_profile_dict`
- `DecodedProfile`
- format/heuristic constants used by experiments and validation guardrails.
"""

from __future__ import annotations

from .api import (  # noqa: F401
    DEFAULT_TAG_LAYOUTS,
    ROLE_UNKNOWN,
    WORD_OFFSET_BYTES,
    DecodedProfile,
    decode_profile,
    decode_profile_dict,
)

__all__ = [
    "DecodedProfile",
    "decode_profile",
    "decode_profile_dict",
    "WORD_OFFSET_BYTES",
    "DEFAULT_TAG_LAYOUTS",
    "ROLE_UNKNOWN",
]

