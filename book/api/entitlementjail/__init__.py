"""
EntitlementJail tooling surface (stable API exports).

Re-exports the small, stable API used by experiments and tooling.
"""

from book.api.entitlementjail.cli import (
    WORLD_ID,
    bundle_evidence,
    run_matrix_group,
    run_xpc,
)
from book.api.entitlementjail.paths import EJ, EJ_APP, LOG_OBSERVER, REPO_ROOT
from book.api.entitlementjail.session import XpcSession
from book.api.entitlementjail.wait import run_probe_wait, run_wait_xpc

__all__ = [
    "EJ",
    "EJ_APP",
    "LOG_OBSERVER",
    "REPO_ROOT",
    "WORLD_ID",
    "bundle_evidence",
    "XpcSession",
    "run_matrix_group",
    "run_probe_wait",
    "run_wait_xpc",
    "run_xpc",
]
