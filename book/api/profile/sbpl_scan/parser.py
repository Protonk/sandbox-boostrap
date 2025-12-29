"""
Minimal SBPL tokenizer/parser (structural, conservative).

This parser is intentionally incomplete: it exists to support cheap structural
scans without needing to evaluate policy semantics.

Design constraints:
- Treat SBPL as an S-expression language with comments.
- Preserve string literals as single tokens (including quotes) so callers can
  distinguish `"foo"` from `foo` without a full evaluator.
- Keep error handling simple and loud — a malformed profile should not quietly
  “parse” into a misleading structure.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from .model import Atom, Expr, ListExpr


def _tokenize_sbpl(text: str) -> List[str]:
    """Tokenize SBPL text into `(`, `)`, string literals, and atoms."""
    tokens: List[str] = []
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]

        # whitespace
        if ch.isspace():
            i += 1
            continue

        # line comment
        if ch == ";":
            while i < n and text[i] != "\n":
                i += 1
            continue

        # block comment (#| ... |#)
        if text.startswith("#|", i):
            end = text.find("|#", i + 2)
            if end == -1:
                # Unterminated block comment: treat remainder as comment.
                break
            i = end + 2
            continue

        if ch == "(" or ch == ")":
            tokens.append(ch)
            i += 1
            continue

        # string literal
        if ch == '"':
            start = i
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            # Keep the quotes in the token so consumers can treat it as a
            # literal without additional context.
            tokens.append(text[start:i])
            continue

        # atom
        start = i
        while i < n:
            ch2 = text[i]
            if ch2.isspace() or ch2 in ("(", ")", ";"):
                break
            if text.startswith("#|", i):
                break
            i += 1
        if start == i:
            # Defensive: avoid infinite loops on unexpected chars.
            i += 1
            continue
        tokens.append(text[start:i])

    return tokens


def _parse_expr(tokens: Sequence[str], idx: int) -> Tuple[Expr, int]:
    """Parse one expression from `tokens[idx:]` and return `(expr, next_idx)`."""
    if idx >= len(tokens):
        raise ValueError("unexpected EOF while parsing SBPL")
    tok = tokens[idx]
    if tok == "(":
        idx += 1
        items: List[Expr] = []
        while True:
            if idx >= len(tokens):
                raise ValueError("unterminated list")
            if tokens[idx] == ")":
                idx += 1
                break
            child, idx = _parse_expr(tokens, idx)
            items.append(child)
        return ListExpr(tuple(items)), idx
    if tok == ")":
        raise ValueError("unexpected ')'")
    return Atom(tok), idx + 1


def parse_sbpl(text: str) -> List[Expr]:
    """
    Parse SBPL source text into a list of top-level expressions.

    SBPL files commonly contain multiple top-level forms (`(version ...)`,
    `(deny ...)`, etc), hence the list return type.
    """
    tokens = _tokenize_sbpl(text)
    exprs: List[Expr] = []
    idx = 0
    while idx < len(tokens):
        expr, idx = _parse_expr(tokens, idx)
        exprs.append(expr)
    return exprs


def list_operator(expr: Expr) -> Optional[str]:
    """
    Return the head symbol for a list form, e.g. `"allow"` for `(allow ...)`.

    Returns `None` for atoms and empty lists.
    """
    if not isinstance(expr, ListExpr) or not expr.items:
        return None
    head = expr.items[0]
    return head.value if isinstance(head, Atom) else None
