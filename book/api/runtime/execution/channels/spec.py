"""
Runtime channel specification (service contract).

`runtime` runs plans through a channel that defines the execution
environment and the guarantees we can make about the resulting evidence.

Today there are two supported channels:
- `direct`: best-effort execution in the current process context. Outputs are
  still written as bundles, but decision-stage evidence is not promotable unless
  an external clean-manifest proves the run started unsandboxed.
- `launchd_clean`: stages the repo and launches a fresh worker via launchd to
  guarantee a clean apply context on this host. This is the canonical
  decision-stage evidence lane.

This module is intentionally small and purely declarative: it does not run
processes or write artifacts; it only carries the knobs that control channel
selection, staging, and bundle-root locking behavior.

A channel captures assumptions about process state. In sandbox work,
starting "clean" can be the difference between a denial and an apply failure.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class ChannelName(StrEnum):
    """Supported channel identifiers for `ChannelSpec.channel`."""

    DIRECT = "direct"
    LAUNCHD_CLEAN = "launchd_clean"


class LockMode(StrEnum):
    """
    Bundle-root lock acquisition mode.

    - `fail`: fail fast if another writer is holding the lock.
    - `wait`: block (bounded by `lock_timeout_seconds`) until the lock is free.
    """

    FAIL = "fail"
    WAIT = "wait"


@dataclass(frozen=True)
class ChannelSpec:
    channel: str = ChannelName.DIRECT
    require_clean: bool = False
    # Staging under /private/tmp avoids slow file operations in the repo tree.
    staging_base: Path = Path("/private/tmp/sandbox-lore-launchctl")
    lock: bool = True
    lock_mode: str = LockMode.FAIL
    lock_timeout_seconds: float = 30.0
    label_prefix: str = "sandbox-lore.runtime"
