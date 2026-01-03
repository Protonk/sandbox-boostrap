"""
Paths and shared constants for PolicyWitness and witness-adjacent helpers.

This module centralizes the repo-local location of PolicyWitness.app and its
embedded helper binaries, plus small witness-side helpers. Import these paths
instead of reconstructing them so callers remain aligned with the fixed layout.
"""

from __future__ import annotations

from pathlib import Path

from book.api import path_utils

# Resolve the fixed, repo-local PolicyWitness app bundle and its helpers.
REPO_ROOT = path_utils.find_repo_root(Path(__file__))
WITNESS_APP = REPO_ROOT / "book" / "tools" / "witness" / "PolicyWitness.app"
WITNESS_CLI = WITNESS_APP / "Contents" / "MacOS" / "policy-witness"
WITNESS_LOG_OBSERVER = WITNESS_APP / "Contents" / "MacOS" / "sandbox-log-observer"
WITNESS_RESOURCES = WITNESS_APP / "Contents" / "Resources"
WITNESS_EVIDENCE = WITNESS_RESOURCES / "Evidence"
WITNESS_EVIDENCE_MANIFEST = WITNESS_EVIDENCE / "manifest.json"
WITNESS_EVIDENCE_PROFILES = WITNESS_EVIDENCE / "profiles.json"
WITNESS_EVIDENCE_SYMBOLS = WITNESS_EVIDENCE / "symbols.json"
WITNESS_HOLD_OPEN = REPO_ROOT / "book" / "api" / "witness" / "native" / "hold_open" / "hold_open"
WITNESS_SB_API_VALIDATOR = REPO_ROOT / "book" / "api" / "witness" / "native" / "sb_api_validator" / "sb_api_validator"
WITNESS_FRIDA_ATTACH_HELPER = REPO_ROOT / "book" / "api" / "frida" / "native" / "attach_helper" / "frida_attach_helper"
WITNESS_FRIDA_ATTACH_HELPER_ENTITLEMENTS = (
    REPO_ROOT / "book" / "api" / "frida" / "native" / "attach_helper" / "entitlements.plist"
)
WITNESS_KEEPALIVE_OUT = REPO_ROOT / "book" / "api" / "witness" / "out" / "keepalive"
