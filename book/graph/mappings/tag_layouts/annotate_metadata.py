#!/usr/bin/env python3
"""
Annotate tag_layouts.json with canonical system-profile status.

This keeps the tag-layout mapping tied to the canonical system profile contracts
and the current world_id pointer so downstream consumers can refuse to treat
tag-layout coverage as ok when canonical profiles drift.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import evidence_tiers  # noqa: E402
from book.api import world as world_mod  # noqa: E402

TAG_LAYOUTS_PATH = ROOT / "book/graph/mappings/tag_layouts/tag_layouts.json"
DIGESTS_PATH = ROOT / "book/graph/mappings/system_profiles/digests.json"


def load_json(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"missing input: {path}")
    return json.loads(path.read_text())


def baseline_world_id() -> str:
    data, resolution = world_mod.load_world(repo_root=ROOT)
    return world_mod.require_world_id(data, world_path=resolution.entry.world_path)


def main() -> None:
    world_id = baseline_world_id()
    tag_layouts = load_json(TAG_LAYOUTS_PATH)
    digests = load_json(DIGESTS_PATH)
    digests_meta = digests.get("metadata") or {}
    canonical_profiles = digests_meta.get("canonical_profiles") or {}
    status = digests_meta.get("status") or "unknown"

    metadata = tag_layouts.get("metadata") or {}
    # Tag-layout health is derivative: it mirrors the canonical profile status
    # and world pointer so consumers know the layouts are only as trustworthy as
    # the profiles they were decoded from. We intentionally do not inject any
    # new judgments about tag layouts here.
    metadata.update(
        {
            "world_id": world_id,
            "status": status,
            "tier": evidence_tiers.evidence_tier_for_artifact(
                path=TAG_LAYOUTS_PATH,
                tier="bedrock" if evidence_tiers.is_bedrock_mapping_path(TAG_LAYOUTS_PATH) else "mapped",
            ),
            "canonical_profiles": {
                pid: (info.get("status") if isinstance(info, dict) else info) for pid, info in canonical_profiles.items()
            },
        }
    )
    tag_layouts["metadata"] = metadata
    TAG_LAYOUTS_PATH.write_text(json.dumps(tag_layouts, indent=2))
    print(f"[+] updated {TAG_LAYOUTS_PATH} (status: {status})")


if __name__ == "__main__":
    main()
