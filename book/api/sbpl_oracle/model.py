from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Tuple


WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"

OracleDim = Literal["domain", "type", "proto"]


@dataclass(frozen=True)
class Record8:
    blob_offset: int
    tag: int
    kind: int
    u16: Tuple[int, int, int]

    def to_dict(self) -> Dict[str, Any]:
        return {"tag": int(self.tag), "kind": int(self.kind), "u16": [int(v) for v in self.u16]}


@dataclass(frozen=True)
class Witness:
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
    dim: OracleDim
    primary: Witness
    other: Witness

    def to_dict(self) -> Dict[str, Any]:
        return {"dim": self.dim, "primary": self.primary.to_dict(), "other": self.other.to_dict()}


@dataclass(frozen=True)
class NetworkTupleResult:
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

