"""
Analysis helpers for runtime bundles and mappings.

Analysis code is intentionally downstream of capture. It should read
bundles and mappings as inputs, not reach back into execution details.
"""

from __future__ import annotations

# Submodules implement concrete analysis helpers; this package stays minimal.
