"""
Import shim for Axis 4.1 Profile Ingestion.

Python package names cannot contain dashes, so this shim loads the implementation
from `profile-ingestion/ingestion.py` and re-exports its public API as
`concepts.cross.profile_ingestion`.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_IMPL_PATH = Path(__file__).resolve().parent / "profile-ingestion" / "ingestion.py"
_SPEC = importlib.util.spec_from_file_location("concepts.cross.profile_ingestion._impl", _IMPL_PATH)
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover - defensive
    raise ImportError(f"Cannot load profile ingestion implementation from {_IMPL_PATH}")
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)  # type: ignore[misc]

# Re-export public API
ProfileBlob = _MODULE.ProfileBlob
ProfileHeader = _MODULE.ProfileHeader
ProfileSections = _MODULE.ProfileSections
UnsupportedProfileFormat = _MODULE.UnsupportedProfileFormat
parse_header = _MODULE.parse_header
slice_sections = _MODULE.slice_sections
detect_format = _MODULE.detect_format
FORMAT_GRAPH_V1 = _MODULE.FORMAT_GRAPH_V1
FORMAT_LEGACY_V1 = _MODULE.FORMAT_LEGACY_V1

__all__ = [
    "FORMAT_GRAPH_V1",
    "FORMAT_LEGACY_V1",
    "ProfileBlob",
    "ProfileHeader",
    "ProfileSections",
    "UnsupportedProfileFormat",
    "parse_header",
    "slice_sections",
    "detect_format",
]
