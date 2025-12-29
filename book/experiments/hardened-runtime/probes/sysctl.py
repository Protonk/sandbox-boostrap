"""Sysctl read probes for hardened-runtime."""

from __future__ import annotations

from pathlib import Path
from typing import List

from book.api.runtime import workflow


ALLOWED_SYSCTL = "kern.osrelease"
DENIED_SYSCTL = "kern.bootargs"
CANARY_SYSCTL = "kern.ostype"


def build_profiles(sb_dir: Path) -> List[workflow.ProfileSpec]:
    profile_path = sb_dir / "sysctl_read.sb"
    probes = [
        {
            "name": "deny-kern-osrelease",
            "operation": "sysctl-read",
            "target": ALLOWED_SYSCTL,
            "expected": "deny",
        },
        {
            "name": "deny-kern-bootargs",
            "operation": "sysctl-read",
            "target": DENIED_SYSCTL,
            "expected": "deny",
        },
    ]
    allow_profile = sb_dir / "sysctl_read_allow.sb"
    allow_probes = [
        {
            "name": "allow-kern-ostype",
            "operation": "sysctl-read",
            "target": CANARY_SYSCTL,
            "expected": "allow",
        }
    ]
    return [
        workflow.ProfileSpec(
            profile_id="hardened:sysctl_read",
            profile_path=profile_path,
            probes=probes,
            family="sysctl_read",
            semantic_group="sysctl:name",
        ),
        workflow.ProfileSpec(
            profile_id="hardened:sysctl_read_allow",
            profile_path=allow_profile,
            probes=allow_probes,
            family="sysctl_read",
            semantic_group="sysctl:name",
        ),
    ]
