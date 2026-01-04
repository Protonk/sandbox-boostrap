"""
Data model for structural oracles over compiled profiles (Sonoma baseline).

Oracles in this repo are deliberately narrow:
- They extract *SBPL-visible argument structure* from compiled blobs.
- They rely on byte-level witnesses established by experiments (e.g.
  `book/evidence/experiments/field2-final-final/libsandbox-encoder/`), not on reverse-engineered kernel semantics.

This file contains only data shapes: the actual oracle logic lives in
`book.api.profile.oracles.network`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Tuple


# World scoping is explicit: oracle outputs are only meaningful on the baseline
# they were witnessed against.
WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-a3a840f9"

OracleDim = Literal["domain", "type", "proto"]


@dataclass(frozen=True)
class Record8:
    """
    One 8-byte node record interpreted as: tag,u8-kind,3*u16.

    This record shape is used by the network tuple oracle because the witness
    patterns (markers and value packing) were observed in record8-framed node
    streams in the network matrix corpus.
    """

    blob_offset: int
    tag: int
    kind: int
    u16: Tuple[int, int, int]

    def to_dict(self) -> Dict[str, Any]:
        return {"tag": int(self.tag), "kind": int(self.kind), "u16": [int(v) for v in self.u16]}


@dataclass(frozen=True)
class Witness:
    """One structural witness tying a value to a record location."""

    dim: OracleDim
    source: str
    value: int
    record: Record8

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "value": int(self.value),
            "blob_offset": int(self.record.blob_offset),
            "record": self.record.to_dict(),
        }


@dataclass(frozen=True)
class Conflict:
    """Represents a disagreement between two witness sources for the same dim."""

    dim: OracleDim
    primary: Witness
    other: Witness

    def to_dict(self) -> Dict[str, Any]:
        return {"dim": self.dim, "primary": self.primary.to_dict(), "other": self.other.to_dict()}


@dataclass(frozen=True)
class NetworkTupleResult:
    """
    Oracle result for `(domain, type, proto)`.

    `sources` and `conflicts` are included to keep the result explainable: you
    can trace every resolved value back to byte offsets in the blob.
    """

    header: Dict[str, Any]
    domain: Optional[int]
    type: Optional[int]
    proto: Optional[int]
    sources: Dict[str, List[Dict[str, Any]]]
    conflicts: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header": dict(self.header),
            "domain": self.domain,
            "type": self.type,
            "proto": self.proto,
            "sources": dict(self.sources),
            "conflicts": list(self.conflicts),
        }
