"""Process-info probes (pidinfo allow/deny)."""

from __future__ import annotations

from pathlib import Path
from typing import List

from book.api.runtime import workflow


def build_profiles(sb_dir: Path) -> List[workflow.ProfileSpec]:
    allow_profile = sb_dir / "process_info_allow.sb"
    allow_canary_profile = sb_dir / "process_info_allow_canary.sb"
    deny_profile = sb_dir / "process_info_deny.sb"
    probes = [
        {
            "name": "pidinfo-self",
            "operation": "process-info-pidinfo",
            "target": "self",
            "expected": "deny",
        },
        {
            "name": "pidinfo-init",
            "operation": "process-info-pidinfo",
            "target": "1",
            "expected": "deny",
        },
    ]
    deny_probes = [dict(probe, expected="deny") for probe in probes]
    allow_canary_probes = [
        {
            "name": "pidinfo-self",
            "operation": "process-info-pidinfo",
            "target": "self",
            "expected": "allow",
        }
    ]
    return [
        workflow.ProfileSpec(
            profile_id="hardened:process_info_allow",
            profile_path=allow_profile,
            probes=probes,
            family="process_info",
            semantic_group="process-info:pidinfo",
        ),
        workflow.ProfileSpec(
            profile_id="hardened:process_info_allow_canary",
            profile_path=allow_canary_profile,
            probes=allow_canary_probes,
            family="process_info",
            semantic_group="process-info:pidinfo",
        ),
        workflow.ProfileSpec(
            profile_id="hardened:process_info_deny",
            profile_path=deny_profile,
            probes=deny_probes,
            family="process_info",
            semantic_group="process-info:pidinfo",
        ),
    ]
