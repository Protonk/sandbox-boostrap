"""
Lifecycle probes for the Sonoma baseline.

This package provides a small, host-bound way to generate lifecycle validation
IR (entitlements + extensions) without keeping runnable code under `book/examples/`.
"""

from __future__ import annotations

from .runner import (  # noqa: F401
    DEFAULT_BUILD_DIR,
    DEFAULT_LIFECYCLE_OUT_DIR,
    DEFAULT_ENTITLEMENTS_OUT,
    DEFAULT_EXTENSIONS_OUT,
    DEFAULT_PLATFORM_OUT,
    DEFAULT_CONTAINERS_OUT,
    DEFAULT_APPLY_ATTEMPT_OUT,
    capture_entitlements_evolution,
    capture_extensions_dynamic,
    capture_platform_policy,
    capture_containers,
    capture_apply_attempt,
    write_validation_out,
)

__all__ = [
    "DEFAULT_BUILD_DIR",
    "DEFAULT_LIFECYCLE_OUT_DIR",
    "DEFAULT_ENTITLEMENTS_OUT",
    "DEFAULT_EXTENSIONS_OUT",
    "DEFAULT_PLATFORM_OUT",
    "DEFAULT_CONTAINERS_OUT",
    "DEFAULT_APPLY_ATTEMPT_OUT",
    "capture_entitlements_evolution",
    "capture_extensions_dynamic",
    "capture_platform_policy",
    "capture_containers",
    "capture_apply_attempt",
    "write_validation_out",
]
