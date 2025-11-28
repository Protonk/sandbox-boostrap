#!/usr/bin/env python3
"""
Lightweight vocabulary extraction scaffold.

Goals:
- Collect decoder-derived metadata (op_count, op_table offsets) from canonical blobs.
- Emit partial vocab artifacts (`out/vocab/ops.json`, `out/vocab/filters.json`)
  with host metadata and source provenance, even if Operation/Filter IDs cannot
  yet be recovered.

This is intentionally conservative: if Operation/Filter name↔ID mapping cannot
be extracted, the artifacts are marked `status: partial` and `entries` remain
empty. This still moves downstream experiments forward by providing structured
provenance and a stable place to plug in real vocab data later.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List

from book.graph.concepts.validation import decoder
from book.graph.concepts.validation import profile_ingestion as pi


@dataclass
class SourceRecord:
    source: str
    length: int
    format_variant: str
    op_count: int
    op_table_offset: int
    op_table_entries: List[int]
    notes: str = ""


def load_host_metadata(out_dir: Path) -> Dict[str, Any]:
    meta_path = out_dir / "metadata.json"
    if meta_path.exists():
        return json.loads(meta_path.read_text())
    return {
        "os": {},
        "sip_status": "unknown",
        "notes": "metadata.json missing; please refresh validation metadata",
    }


def decode_blob(path: Path) -> SourceRecord:
    data = path.read_bytes()
    dec = decoder.decode_profile_dict(data)
    header = pi.parse_header(pi.ProfileBlob(bytes=data, source=path.name))
    op_count = dec.get("op_count") or header.operation_count or 0
    op_table_offset = dec.get("op_table_offset") or 0
    entries = dec.get("op_table") or []
    return SourceRecord(
        source=str(path),
        length=len(data),
        format_variant=dec.get("format_variant") or header.format_variant or "unknown",
        op_count=op_count,
        op_table_offset=op_table_offset,
        op_table_entries=entries,
        notes="decoder-derived metadata only; no name↔ID mapping yet",
    )


def collect_sources() -> List[SourceRecord]:
    roots = [
        Path("book/examples/extract_sbs/build/profiles"),
        Path("book/examples/sb/build"),
    ]
    blobs: List[SourceRecord] = []
    for root in roots:
        if not root.exists():
            continue
        for binpath in sorted(root.glob("*.sb.bin")):
            try:
                blobs.append(decode_blob(binpath))
            except Exception as exc:  # pragma: no cover
                blobs.append(
                    SourceRecord(
                        source=str(binpath),
                        length=binpath.stat().st_size,
                        format_variant="unknown",
                        op_count=0,
                        op_table_offset=0,
                        op_table_entries=[],
                        notes=f"decode failed: {exc}",
                    )
                )
    return blobs


def write_vocab_stub(out_dir: Path, kind: str, host_meta: Dict[str, Any], sources: List[SourceRecord]) -> None:
    vocab_path = out_dir / f"{kind}.json"
    vocab = {
        "status": "partial",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": host_meta.get("os", {}),
        "profile_format_variant": host_meta.get("profile_format_variant", "unknown"),
        "sources": [asdict(s) for s in sources],
        f"{kind}": [],
        "notes": f"{kind} vocabulary extraction not implemented; decoder metadata only.",
    }
    vocab_path.write_text(json.dumps(vocab, indent=2, sort_keys=True))
    print(f"[+] wrote {vocab_path}")


def main() -> None:
    base = Path("book/graph/concepts/validation")
    out_dir = base / "out" / "vocab"
    out_dir.mkdir(parents=True, exist_ok=True)
    host_meta = load_host_metadata(base / "out")
    sources = collect_sources()
    write_vocab_stub(out_dir, "ops", host_meta, sources)
    write_vocab_stub(out_dir, "filters", host_meta, sources)


if __name__ == "__main__":
    main()
