#!/usr/bin/env python3
"""Generate a mac_policy_ops layout map from a local header file.

This parser expects a preprocessed header (or a plain header where
struct mac_policy_ops is fully expanded). It extracts mpo_* field names
in declaration order and assigns offsets assuming pointer-sized fields.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import List, Optional

from book.api import path_utils


_STRUCT_RE = re.compile(r"struct\s+mac_policy_ops\b")
_FIELD_RE = re.compile(r"\(\s*\*\s*(mpo_[A-Za-z0-9_]+)\s*\)")
_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.DOTALL | re.MULTILINE)


def _strip_comments(text: str) -> str:
    return re.sub(_COMMENT_RE, "", text)


def _extract_struct_body(text: str) -> Optional[str]:
    match = _STRUCT_RE.search(text)
    if not match:
        return None
    start = text.find("{", match.end())
    if start < 0:
        return None
    depth = 0
    body_chars: List[str] = []
    for ch in text[start:]:
        if ch == "{":
            depth += 1
            if depth == 1:
                continue
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
        if depth >= 1:
            body_chars.append(ch)
    return "".join(body_chars)


def _extract_fields(body: str) -> List[str]:
    return [match.group(1) for match in _FIELD_RE.finditer(body)]


def _header_ref(header_path: Path, repo_root: Path) -> dict:
    try:
        ref = path_utils.to_repo_relative(header_path, repo_root)
        return {"path": ref, "external": False}
    except Exception:
        return {"path": header_path.name, "external": True}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build mac_policy_ops layout map from header")
    parser.add_argument("--header", required=True, help="Path to mac_policy.h (prefer preprocessed)")
    parser.add_argument("--out", required=True, help="Output JSON path")
    parser.add_argument("--ptr-size", type=int, default=8, help="Pointer size in bytes (default: 8)")
    parser.add_argument("--xnu", default=None, help="Optional XNU build string for metadata")
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root()
    header_path = path_utils.ensure_absolute(Path(args.header), repo_root)
    out_path = path_utils.ensure_absolute(Path(args.out), repo_root)

    text = header_path.read_text()
    body = _extract_struct_body(_strip_comments(text))
    if not body:
        raise SystemExit("struct mac_policy_ops not found in header")

    fields = _extract_fields(body)
    if not fields:
        raise SystemExit("No mpo_* fields found in struct mac_policy_ops")

    ptr_size = args.ptr_size
    layout = {
        "meta": {
            "source_header": _header_ref(header_path, repo_root),
            "xnu": args.xnu,
        },
        "ptr_size": ptr_size,
        "struct_size": len(fields) * ptr_size,
        "fields": [
            {"name": name, "offset": idx * ptr_size}
            for idx, name in enumerate(fields)
        ],
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(layout, indent=2, sort_keys=True))
    print("Wrote", path_utils.to_repo_relative(out_path, repo_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
