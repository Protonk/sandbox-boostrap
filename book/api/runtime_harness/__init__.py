"""
Unified runtime harness for the Sonoma baseline.

This package merges the former `runtime_golden` (generation/normalization)
and `golden_runner` (execution of expected matrices) surfaces.
"""

from __future__ import annotations

from .generate import (  # noqa: F401
    GOLDEN_KEYS,
    BaselineInfo,
    GoldenProfile,
    compile_profile,
    decode_profile,
    load_baseline,
    load_matrix,
    normalize_runtime_results,
    sha256_bytes,
    summarize_decode,
)
from .runner import (  # noqa: F401
    DEFAULT_OUT,
    DEFAULT_RUNTIME_PROFILE_DIR,
    ensure_tmp_files,
    run_expected_matrix,
    prepare_runtime_profile,
    classify_status,
)

__all__ = [
    "GOLDEN_KEYS",
    "BaselineInfo",
    "GoldenProfile",
    "compile_profile",
    "decode_profile",
    "load_baseline",
    "load_matrix",
    "normalize_runtime_results",
    "sha256_bytes",
    "summarize_decode",
    "DEFAULT_OUT",
    "DEFAULT_RUNTIME_PROFILE_DIR",
    "ensure_tmp_files",
    "run_expected_matrix",
    "prepare_runtime_profile",
    "classify_status",
]
