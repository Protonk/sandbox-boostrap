"""Probe families for hardened-runtime (non-VFS surfaces only)."""

from __future__ import annotations

from pathlib import Path
from typing import List

from book.api.runtime import workflow

from .mach import build_profiles as build_mach_profiles
from .sysctl import build_profiles as build_sysctl_profiles
from .iokit import build_profiles as build_iokit_profiles
from .process_info import build_profiles as build_process_info_profiles
from .system_socket import build_profiles as build_system_socket_profiles
from .notifications import build_profiles as build_notifications_profiles
from .signal import build_profiles as build_signal_profiles
from .xpc import build_profiles as build_xpc_profiles


def build_all_profiles(sb_dir: Path) -> List[workflow.ProfileSpec]:
    profiles: List[workflow.ProfileSpec] = []
    for builder in (
        build_mach_profiles,
        build_sysctl_profiles,
        build_iokit_profiles,
        build_process_info_profiles,
        build_system_socket_profiles,
        build_notifications_profiles,
        build_signal_profiles,
        build_xpc_profiles,
    ):
        profiles.extend(builder(sb_dir))
    return profiles
