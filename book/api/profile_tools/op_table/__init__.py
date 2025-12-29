"""
Op-table centric helpers (Sonoma baseline).
"""

from __future__ import annotations

from .api import (  # noqa: F401
    Summary,
    ascii_strings,
    build_alignment,
    entry_signature,
    load_vocab,
    op_entries,
    parse_filters,
    parse_ops,
    summarize_profile,
    tag_counts,
)

__all__ = [
    "Summary",
    "parse_ops",
    "parse_filters",
    "summarize_profile",
    "entry_signature",
    "build_alignment",
    "load_vocab",
    "op_entries",
    "tag_counts",
    "ascii_strings",
]

