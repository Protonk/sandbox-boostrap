"""Signal-to-self probes for hardened-runtime."""

from __future__ import annotations

from pathlib import Path
from typing import List

from book.api.runtime.execution import workflow


def build_profiles(sb_dir: Path) -> List[workflow.ProfileSpec]:
    allow_path = sb_dir / "signal_self_allow.sb"
    deny_path = sb_dir / "signal_self_deny.sb"
    allow_probes = [
        {
            "name": "signal-same-sandbox",
            "operation": "signal",
            "target": "same-sandbox",
            "expected": "allow",
        }
    ]
    deny_probes = [
        {
            "name": "signal-same-sandbox",
            "operation": "signal",
            "target": "same-sandbox",
            "expected": "deny",
        }
    ]
    return [
        workflow.ProfileSpec(
            profile_id="hardened:signal_self_allow",
            profile_path=allow_path,
            probes=allow_probes,
            family="signal",
            semantic_group="signal:self",
        ),
        workflow.ProfileSpec(
            profile_id="hardened:signal_self_deny",
            profile_path=deny_path,
            probes=deny_probes,
            family="signal",
            semantic_group="signal:self",
        ),
    ]
