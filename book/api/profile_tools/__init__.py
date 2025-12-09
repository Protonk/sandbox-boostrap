"""
Unified profile tooling for the Sonoma Seatbelt baseline.

This package folds the former `sbpl_compile`, `inspect_profile`, and
`op_table` helpers into one surface while keeping the existing modules
as shims. All functions remain Sonoma-specific and reuse the same
vocab/tag-layout mappings.
"""

from __future__ import annotations

from . import compile as compile  # noqa: F401
from .compile import CompileResult, compile_sbpl_file, compile_sbpl_string, default_output_for, hex_preview  # noqa: F401
from . import inspect as inspect  # noqa: F401
from .inspect import Summary as InspectSummary, load_blob, summarize_blob  # noqa: F401
from . import op_table as op_table  # noqa: F401
from .op_table import (  # noqa: F401
    Summary as OpTableSummary,
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
    # compile
    "CompileResult",
    "compile_sbpl_file",
    "compile_sbpl_string",
    "default_output_for",
    "hex_preview",
    # inspect
    "InspectSummary",
    "load_blob",
    "summarize_blob",
    # op_table
    "OpTableSummary",
    "ascii_strings",
    "build_alignment",
    "entry_signature",
    "load_vocab",
    "op_entries",
    "parse_filters",
    "parse_ops",
    "summarize_profile",
    "tag_counts",
]
