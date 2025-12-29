"""Mach/XPC lookup probes (global-name) for hardened-runtime."""

from __future__ import annotations

from pathlib import Path
from typing import List

from book.api.runtime import workflow


ALLOWED_SERVICE = "com.apple.cfprefsd.agent"
DENIED_SERVICE = "com.apple.sandbox-lore.hardened-runtime.bogus"


def build_profiles(sb_dir: Path) -> List[workflow.ProfileSpec]:
    profile_path = sb_dir / "mach_lookup.sb"
    probes = [
        {
            "name": "deny-cfprefsd",
            "operation": "mach-lookup",
            "target": ALLOWED_SERVICE,
            "expected": "deny",
        },
        {
            "name": "deny-bogus",
            "operation": "mach-lookup",
            "target": DENIED_SERVICE,
            "expected": "deny",
        },
    ]
    allow_profile = sb_dir / "mach_lookup_allow.sb"
    allow_probes = [
        {
            "name": "allow-cfprefsd",
            "operation": "mach-lookup",
            "target": ALLOWED_SERVICE,
            "expected": "allow",
        }
    ]
    return [
        workflow.ProfileSpec(
            profile_id="hardened:mach_lookup",
            profile_path=profile_path,
            probes=probes,
            family="mach_lookup",
            semantic_group="mach:global-name",
        ),
        workflow.ProfileSpec(
            profile_id="hardened:mach_lookup_allow",
            profile_path=allow_profile,
            probes=allow_probes,
            family="mach_lookup",
            semantic_group="mach:global-name",
        ),
    ]
