"""
Structural “oracle” helpers for compiled sandbox profiles (Sonoma baseline).

These helpers extract SBPL-visible argument structure from compiled blobs using
byte-level witnesses established by experiment corpora. They are intentionally
structural and do not claim kernel semantics.
"""

from __future__ import annotations

from .model import WORLD_ID, Conflict, NetworkTupleResult, OracleDim, Record8, Witness  # noqa: F401
from .network import extract_network_tuple  # noqa: F401

__all__ = [
    "WORLD_ID",
    "OracleDim",
    "Record8",
    "Witness",
    "Conflict",
    "NetworkTupleResult",
    "extract_network_tuple",
]
