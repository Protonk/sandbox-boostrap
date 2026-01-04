"""Protocol helpers for PolicyWitness `xpc session`."""

from __future__ import annotations

import errno
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple


@dataclass(frozen=True)
class WaitSpec:
    """Typed wait spec for `policy-witness xpc session --wait`."""

    kind: str
    path: Optional[str] = None

    def to_arg(self) -> str:
        if self.kind not in {"fifo", "exists"}:
            raise ValueError(f"unsupported wait spec kind: {self.kind}")
        if self.path is None:
            if self.kind != "fifo":
                raise ValueError("auto wait path is only supported for fifo waits")
            return "fifo:auto"
        return f"{self.kind}:{self.path}"

    @classmethod
    def fifo_auto(cls) -> "WaitSpec":
        return cls(kind="fifo", path=None)

    @classmethod
    def fifo(cls, path: str) -> "WaitSpec":
        return cls(kind="fifo", path=path)

    @classmethod
    def exists(cls, path: str) -> "WaitSpec":
        return cls(kind="exists", path=path)


def normalize_wait_spec(wait_spec: Optional[WaitSpec | str]) -> Optional[str]:
    if wait_spec is None:
        return None
    if isinstance(wait_spec, WaitSpec):
        return wait_spec.to_arg()
    if isinstance(wait_spec, str):
        return wait_spec
    raise TypeError(f"unsupported wait_spec type: {type(wait_spec).__name__}")


def parse_wait_spec(wait_spec: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not wait_spec:
        return None, None
    if wait_spec.startswith("fifo:"):
        path = wait_spec.split("fifo:", 1)[1]
        return "fifo", None if path == "auto" else path
    if wait_spec.startswith("exists:"):
        path = wait_spec.split("exists:", 1)[1]
        return "exists", path
    return None, None


def trigger_wait_path(
    *,
    wait_path: str,
    wait_mode: str,
    nonblocking: bool,
    timeout_s: float,
) -> Optional[str]:
    if wait_mode == "fifo":
        return _trigger_fifo(Path(wait_path), nonblocking=nonblocking, timeout_s=timeout_s)
    if wait_mode == "exists":
        return _trigger_exists(Path(wait_path))
    return f"unknown_wait_mode:{wait_mode}"


def _trigger_fifo(path: Path, *, nonblocking: bool, timeout_s: float) -> Optional[str]:
    try:
        flags = os.O_WRONLY | os.O_NONBLOCK
        deadline = time.monotonic() + max(timeout_s, 0.0)
        while True:
            try:
                fd = os.open(str(path), flags)
            except OSError as exc:
                if nonblocking:
                    return f"{type(exc).__name__}: {exc}"
                if exc.errno == errno.ENXIO and time.monotonic() <= deadline:
                    time.sleep(0.05)
                    continue
                return f"{type(exc).__name__}: {exc}"
            try:
                os.write(fd, b"go")
            finally:
                os.close(fd)
            return None
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


def _trigger_exists(path: Path) -> Optional[str]:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("go")
        return None
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"
