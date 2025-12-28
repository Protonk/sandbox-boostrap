#!/usr/bin/env python3
"""
Regenerate the preamble/header contract for the canonical system profile blobs.

Output:
- book/graph/mappings/system_profiles/header_contract.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api import evidence_tiers  # type: ignore
from book.api.profile_tools import digests as digests_mod  # type: ignore
from book.api import world as world_mod  # type: ignore
OUT_PATH = REPO_ROOT / "book/graph/mappings/system_profiles/header_contract.json"


def baseline_world_id() -> str:
    data, resolution = world_mod.load_world(repo_root=REPO_ROOT)
    return world_mod.require_world_id(data, world_path=resolution.entry.world_path)


def header_words_u16(blob: bytes) -> list[int]:
    return [int.from_bytes(blob[i : i + 2], "little") for i in range(0, min(len(blob), 16), 2)]


def summarize_blob(path: Path) -> Dict[str, Any]:
    blob = path.read_bytes()
    words = header_words_u16(blob)
    return {
        "source": to_repo_relative(path, REPO_ROOT),
        "length": len(blob),
        "header_words": words,
        "op_count_word": words[1] if len(words) > 1 else None,
        "maybe_flags_word": words[0] if words else None,
    }


def main() -> None:
    world_id = baseline_world_id()
    canonical = digests_mod.canonical_system_profile_blobs(REPO_ROOT)
    profiles = {
        "sys:airlock": canonical["airlock"],
        "sys:bsd": canonical["bsd"],
        "sys:sample": canonical["sample"],
    }
    payload = {
        "metadata": {
            "world_id": world_id,
            "status": "ok",
            "tier": evidence_tiers.evidence_tier_for_artifact(
                path=OUT_PATH,
                tier="mapped",
            ),
            "inputs": [to_repo_relative(p, REPO_ROOT) for p in profiles.values()],
            "notes": "Preamble (first 16 bytes) contract for canonical system profiles on this host.",
            "source_jobs": ["generator:system_profiles:header_contract"],
        },
        "profiles": {profile_id: summarize_blob(path) for profile_id, path in profiles.items()},
    }

    OUT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[+] wrote {to_repo_relative(OUT_PATH, REPO_ROOT)}")


if __name__ == "__main__":
    main()
