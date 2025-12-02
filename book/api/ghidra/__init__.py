"""
Public surface for the book/api Ghidra connector.
"""

from .connector import (
    HeadlessConnector,
    HeadlessInvocation,
    HeadlessResult,
    TaskRegistry,
    TaskSpec,
)

__all__ = [
    "HeadlessConnector",
    "HeadlessInvocation",
    "HeadlessResult",
    "TaskRegistry",
    "TaskSpec",
]
