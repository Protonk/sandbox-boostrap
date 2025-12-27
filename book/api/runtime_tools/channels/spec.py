from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ChannelSpec:
    channel: str = "direct"
    require_clean: bool = False
    staging_base: Path = Path("/private/tmp/sandbox-lore-launchctl")
    lock: bool = True
    label_prefix: str = "sandbox-lore.runtime-tools"
