"""
Shim over `book.api.profile_tools.op_table`.

Kept for backward compatibility; prefer importing from
`book.api.profile_tools`.
"""

from __future__ import annotations

import warnings

from book.api.profile_tools import op_table as _profile_op

Summary = _profile_op.Summary
parse_ops = _profile_op.parse_ops
parse_filters = _profile_op.parse_filters
op_entries = _profile_op.op_entries
tag_counts = _profile_op.tag_counts
ascii_strings = _profile_op.ascii_strings
entry_signature = _profile_op.entry_signature
build_alignment = _profile_op.build_alignment
load_vocab = _profile_op.load_vocab


def _warn() -> None:
    warnings.warn(
        "book.api.op_table is deprecated; use book.api.profile_tools (op_table submodule)",
        DeprecationWarning,
        stacklevel=2,
    )


def summarize_profile(
    name: str,
    blob: bytes,
    ops: list[str],
    filters: list[str],
    op_count_override: int | None = None,
    filter_map: dict[str, int] | None = None,
) -> Summary:
    _warn()
    return _profile_op.summarize_profile(
        name=name,
        blob=blob,
        ops=ops,
        filters=filters,
        op_count_override=op_count_override,
        filter_map=filter_map,
    )


__all__ = [
    "Summary",
    "parse_ops",
    "parse_filters",
    "op_entries",
    "tag_counts",
    "ascii_strings",
    "entry_signature",
    "summarize_profile",
    "build_alignment",
    "load_vocab",
]
