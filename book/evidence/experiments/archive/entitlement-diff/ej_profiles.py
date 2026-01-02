"""EntitlementJail profile and service ids used by entitlement-diff."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProfileSpec:
    label: str
    profile_id: str
    service_id: str


PROFILES = {
    "minimal": ProfileSpec(
        label="minimal",
        profile_id="minimal",
        service_id="com.yourteam.entitlement-jail.ProbeService_minimal",
    ),
    "bookmarks_app_scope": ProfileSpec(
        label="bookmarks_app_scope",
        profile_id="bookmarks_app_scope",
        service_id="com.yourteam.entitlement-jail.ProbeService_bookmarks_app_scope",
    ),
    "downloads_rw": ProfileSpec(
        label="downloads_rw",
        profile_id="downloads_rw",
        service_id="com.yourteam.entitlement-jail.ProbeService_downloads_rw",
    ),
    "net_client": ProfileSpec(
        label="net_client",
        profile_id="net_client",
        service_id="com.yourteam.entitlement-jail.ProbeService_net_client",
    ),
}

MATRIX_GROUPS = ("baseline", "debug", "inject", "jit")
