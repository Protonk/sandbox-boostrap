"""Notification probes (darwin + distributed post)."""

from __future__ import annotations

from pathlib import Path
from typing import List

from book.api.runtime import workflow


ALLOW_NAME = "com.sandboxlore.hardened_runtime.test1"
DENY_NAME = "com.sandboxlore.hardened_runtime.test2"


def build_profiles(sb_dir: Path) -> List[workflow.ProfileSpec]:
    profile_path = sb_dir / "notifications.sb"
    probes = [
        {
            "name": "deny-allowed-darwin",
            "operation": "darwin-notification-post",
            "target": ALLOW_NAME,
            "expected": "deny",
        },
        {
            "name": "deny-darwin",
            "operation": "darwin-notification-post",
            "target": DENY_NAME,
            "expected": "deny",
        },
        {
            "name": "deny-allowed-distributed",
            "operation": "distributed-notification-post",
            "target": ALLOW_NAME,
            "expected": "deny",
        },
        {
            "name": "deny-distributed",
            "operation": "distributed-notification-post",
            "target": DENY_NAME,
            "expected": "deny",
        },
    ]
    allow_profile = sb_dir / "notifications_allow.sb"
    allow_probes = [
        {
            "name": "allow-darwin",
            "operation": "darwin-notification-post",
            "target": ALLOW_NAME,
            "expected": "allow",
        },
        {
            "name": "allow-distributed",
            "operation": "distributed-notification-post",
            "target": ALLOW_NAME,
            "expected": "allow",
        },
    ]
    return [
        workflow.ProfileSpec(
            profile_id="hardened:notifications",
            profile_path=profile_path,
            probes=probes,
            family="notifications",
            semantic_group="notifications:post",
        ),
        workflow.ProfileSpec(
            profile_id="hardened:notifications_allow",
            profile_path=allow_profile,
            probes=allow_probes,
            family="notifications",
            semantic_group="notifications:post",
        ),
    ]
