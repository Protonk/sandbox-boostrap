"""
Public surface for the book/api Ghidra connector.

This package re-exports the primary connector and registry entrypoints so
callers can discover tasks without reaching into internal modules.
"""

# Re-export only the stable API so scripts/tests don't depend on internal layout.
from .connector import (
    ARM64_ANALYSIS_PROPERTIES,
    HeadlessConnector,
    HeadlessInvocation,
    HeadlessResult,
    TaskRegistry,
    TaskSpec,
)
from . import registry, run_data_define, run_task

# Keep __all__ explicit so imports remain stable for external callers.
__all__ = [
    "HeadlessConnector",
    "HeadlessInvocation",
    "HeadlessResult",
    "TaskRegistry",
    "TaskSpec",
    "run_data_define",
    "run_task",
    "registry",
    "ARM64_ANALYSIS_PROPERTIES",
]
