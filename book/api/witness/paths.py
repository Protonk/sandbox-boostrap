"""
Paths and shared constants for the PolicyWitness tool bundle.

This module centralizes the repo-local location of PolicyWitness.app and its
embedded helper binaries. Import these paths instead of reconstructing them so
callers remain aligned with the fixed tool bundle layout.
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
