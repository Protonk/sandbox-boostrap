"""
Data model for the minimal SBPL parser used by `book.api.profile.sbpl_scan`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple, Union


@dataclass(frozen=True)
class Atom:
    value: str


@dataclass(frozen=True)
class ListExpr:
    items: Tuple["Expr", ...]


Expr = Union[Atom, ListExpr]

