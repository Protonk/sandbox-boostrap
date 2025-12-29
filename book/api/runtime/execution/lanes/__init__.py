"""
Lane-specific helpers for baseline, mismatch, and path witness artifacts.

Lanes are separate evidence streams (scenario vs baseline vs oracle).
Keeping them explicit prevents us from mixing signals.
"""

from __future__ import annotations

# Individual lane helpers live in submodules to keep imports focused.
