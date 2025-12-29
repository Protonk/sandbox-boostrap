"""
Profile ingestion helpers (Sonoma baseline).

This is the public, stable import surface for header parsing and section slicing
of compiled sandbox profile blobs.
"""

from __future__ import annotations

from .api import (  # noqa: F401
    Header,
    ProfileBlob,
    SectionOffsets,
    Sections,
    parse_header,
    slice_sections,
    slice_sections_with_offsets,
)

__all__ = [
    "ProfileBlob",
    "Header",
    "Sections",
    "SectionOffsets",
    "parse_header",
    "slice_sections",
    "slice_sections_with_offsets",
]

