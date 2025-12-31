"""
Paths and shared constants for PolicyWitness tooling.

This module centralizes the repo-local location of PolicyWitness.app and its
embedded helper binaries. Import these paths instead of reconstructing them so
callers remain aligned with the fixed tool bundle layout.
"""

from __future__ import annotations

from pathlib import Path

from book.api import path_utils

# Resolve the fixed, repo-local PolicyWitness app bundle and its helpers.
REPO_ROOT = path_utils.find_repo_root(Path(__file__))
PW_APP = REPO_ROOT / "book" / "tools" / "witness" / "PolicyWitness.app"
PW = PW_APP / "Contents" / "MacOS" / "policy-witness"
LOG_OBSERVER = PW_APP / "Contents" / "MacOS" / "sandbox-log-observer"
PW_RESOURCES = PW_APP / "Contents" / "Resources"
PW_EVIDENCE = PW_RESOURCES / "Evidence"
PW_EVIDENCE_MANIFEST = PW_EVIDENCE / "manifest.json"
PW_EVIDENCE_PROFILES = PW_EVIDENCE / "profiles.json"
PW_EVIDENCE_SYMBOLS = PW_EVIDENCE / "symbols.json"
