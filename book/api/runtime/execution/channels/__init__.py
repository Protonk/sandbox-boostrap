"""
Execution channels for runtime runs.

A channel defines *how* a run is executed (direct vs clean), which
matters because process state affects sandbox results.
"""

from __future__ import annotations

from .spec import ChannelSpec

# Re-export the channel spec for the public API surface.
__all__ = ["ChannelSpec"]
