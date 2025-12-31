"""
PolicyWitness tooling surface (stable API exports).

Re-exports the small, stable API used by experiments and tooling.
"""

from book.api.policywitness.cli import (
    WORLD_ID,
    bundle_evidence,
    describe_service,
    health_check,
    inspect_macho,
    list_profiles,
    list_services,
    load_evidence_manifest,
    load_evidence_profiles,
    load_evidence_symbols,
    quarantine_lab,
    run_matrix,
    run_matrix_group,
    run_xpc,
    show_profile,
    verify_evidence,
)
from book.api.policywitness.paths import LOG_OBSERVER, PW, PW_APP, REPO_ROOT
from book.api.policywitness.protocol import WaitSpec
from book.api.policywitness.session import XpcSession, open_session

__all__ = [
    "LOG_OBSERVER",
    "PW",
    "PW_APP",
    "REPO_ROOT",
    "WORLD_ID",
    "bundle_evidence",
    "describe_service",
    "health_check",
    "inspect_macho",
    "list_profiles",
    "list_services",
    "load_evidence_manifest",
    "load_evidence_profiles",
    "load_evidence_symbols",
    "quarantine_lab",
    "run_matrix",
    "XpcSession",
    "open_session",
    "WaitSpec",
    "run_matrix_group",
    "run_xpc",
    "show_profile",
    "verify_evidence",
]
