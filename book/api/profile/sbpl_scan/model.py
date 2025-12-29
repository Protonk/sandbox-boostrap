"""
Data model for the minimal SBPL parser used by `book.api.profile.sbpl_scan`.

This AST is intentionally tiny:
- It is sufficient for structural scans (finding certain forms / tokens).
- It is not intended to be a complete SBPL evaluator or linter.

If you are looking for semantics, you are in the wrong layer — this repo treats
SBPL parsing as an input preflight, not a policy engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple, Union


@dataclass(frozen=True)
class Atom:
    """An atomic token (symbol or string literal)."""

    value: str


@dataclass(frozen=True)
class ListExpr:
    """A parenthesized list form, e.g. `(allow file-read ...)`."""

    items: Tuple["Expr", ...]


Expr = Union[Atom, ListExpr]
