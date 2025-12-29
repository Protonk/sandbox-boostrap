"""
Unified profile tooling for the Sonoma Seatbelt baseline.

This package folds the former `sbpl_compile`, `inspect_profile`, and `op_table`
helpers into one surface.

The standalone decoder/oracle endpoints (`book.api.decoder`,
`book.api.sbpl_oracle`) have been removed; use `book.api.profile`.

Preferred imports:
- `from book.api.profile import compile, ingestion, decoder, inspect, op_table, digests, oracles`
- Keep top-level convenience imports (e.g. `compile_sbpl_file`, `decode_profile_dict`) to a minimum.
"""

from __future__ import annotations

# Submodules are the preferred import surface.
from . import cli as cli  # noqa: F401
from . import compile as compile  # noqa: F401
from . import decoder as decoder  # noqa: F401
from . import digests as digests  # noqa: F401
from . import ingestion as ingestion  # noqa: F401
from . import identity as identity  # noqa: F401
from . import inspect as inspect  # noqa: F401
from . import libsandbox as libsandbox  # noqa: F401
from . import op_table as op_table  # noqa: F401
from . import oracles as oracles  # noqa: F401
from . import sbpl_scan as sbpl_scan  # noqa: F401

# Small stable convenience surface (keep this list intentionally short).
from .compile import CompileResult, compile_sbpl_file, compile_sbpl_string, hex_preview  # noqa: F401
from .decoder import DecodedProfile, decode_profile, decode_profile_dict  # noqa: F401
from .digests import canonical_system_profile_blobs, digest_compiled_blob_path, digest_named_blobs  # noqa: F401
from .ingestion import (  # noqa: F401
    Header,
    ProfileBlob,
    SectionOffsets,
    Sections,
    parse_header,
    slice_sections,
    slice_sections_with_offsets,
)

__all__ = [
    # modules
    "cli",
    "compile",
    "decoder",
    "digests",
    "ingestion",
    "identity",
    "inspect",
    "libsandbox",
    "op_table",
    "oracles",
    "sbpl_scan",
    # compile
    "CompileResult",
    "compile_sbpl_file",
    "compile_sbpl_string",
    "hex_preview",
    # decoder
    "DecodedProfile",
    "decode_profile",
    "decode_profile_dict",
    # ingestion
    "ProfileBlob",
    "Header",
    "SectionOffsets",
    "Sections",
    "parse_header",
    "slice_sections",
    "slice_sections_with_offsets",
    # digests
    "canonical_system_profile_blobs",
    "digest_compiled_blob_path",
    "digest_named_blobs",
]
