"""
Unified profile tooling for the Sonoma Seatbelt baseline.

This package folds the former `sbpl_compile`, `inspect_profile`, and `op_table`
helpers into one surface.

The standalone decoder/oracle endpoints (`book.api.decoder`,
`book.api.sbpl_oracle`) have been removed; use `book.api.profile`.

Scope / non-goals:
- This is a *structural* toolkit for working with compiled sandbox profile bytes
  on a pinned host baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).
- It does not claim kernel policy semantics. For policy questions, consume the
  mapped artifacts under `book/graph/mappings/` and the CARTON bundle under
  `book/integration/carton/bundle/` (relationships/views/contracts + manifest), and treat decoder
  output as evidence-tiered (bedrock/mapped/hypothesis).

Subpackages (functional groups):
- `compile`: SBPL → compiled blob bytes (host-required; uses private libsandbox).
- `ingestion`: header + section slicing contract (host-neutral).
- `decoder`: best-effort node annotation for blobs (host-neutral).
- `inspect`: compact blob summaries (host-neutral).
- `op_table`: op-table summaries + vocab alignment helpers (host-neutral).
- `digests`: stable digest emission for curated blobs (host-neutral).
- `identity`: mapping-join helpers for canonical system profiles (host-neutral).
- `oracles`: small structural oracles (currently network tuple) (host-neutral).
- `sbpl_scan`: conservative SBPL scanners used by preflight tooling (host-neutral).

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
