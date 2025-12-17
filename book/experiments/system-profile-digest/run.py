#!/usr/bin/env python3
"""
Regenerate experiment-local digests for the curated canonical system profile blobs.

This writes `book/experiments/system-profile-digest/out/digests.json`, which is then
normalized into validation IR by the job `experiment:system-profile-digest` and
promoted into `book/graph/mappings/system_profiles/digests.json`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import book.api.decoder as decoder  # type: ignore
from book.api.path_utils import to_repo_relative  # type: ignore


CANONICAL: Dict[str, Path] = {
    "airlock": ROOT / "book/examples/extract_sbs/build/profiles/airlock.sb.bin",
    "bsd": ROOT / "book/examples/extract_sbs/build/profiles/bsd.sb.bin",
    "sample": ROOT / "book/examples/sb/build/sample.sb.bin",
}


def summarize(path: Path) -> dict:
    decoded = decoder.decode_profile_dict(path.read_bytes())
    keep_keys = {
        "format_variant",
        "op_count",
        "op_table_offset",
        "op_table",
        "node_count",
        "tag_counts",
        "literal_strings",
        "literal_strings_with_offsets",
        "sections",
        "validation",
    }
    body = {k: decoded[k] for k in sorted(keep_keys) if k in decoded}
    body["source"] = to_repo_relative(path, ROOT)
    return body


def main() -> None:
    out_dir = ROOT / "book/experiments/system-profile-digest/out"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "digests.json"

    payload = {}
    for name, path in CANONICAL.items():
        if not path.exists():
            raise FileNotFoundError(f"missing canonical profile blob: {path}")
        payload[name] = summarize(path)

    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[+] wrote {to_repo_relative(out_path, ROOT)}")


if __name__ == "__main__":
    main()

