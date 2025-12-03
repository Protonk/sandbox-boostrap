"""
Public surface for the book/api Ghidra connector.
"""

from .connector import (
    ARM64_ANALYSIS_PROPERTIES,
    HeadlessConnector,
    HeadlessInvocation,
    HeadlessResult,
    TaskRegistry,
    TaskSpec,
)
from . import run_data_define, run_task

__all__ = [
    "HeadlessConnector",
    "HeadlessInvocation",
    "HeadlessResult",
    "TaskRegistry",
    "TaskSpec",
    "run_data_define",
    "run_task",
    "ARM64_ANALYSIS_PROPERTIES",
]
