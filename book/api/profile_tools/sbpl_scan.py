"""
Static SBPL scanners for host-specific, operational constraints.

These scanners are intentionally conservative and structural: they exist to
avoid "dead-end" runtime probe plans where a profile cannot be applied by the
current harness identity on this world.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


@dataclass(frozen=True)
class Atom:
    value: str


@dataclass(frozen=True)
class ListExpr:
    items: Tuple["Expr", ...]


Expr = Union[Atom, ListExpr]


def _tokenize_sbpl(text: str) -> List[str]:
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
    tokens = _tokenize_sbpl(text)
    exprs: List[Expr] = []
    idx = 0
    while idx < len(tokens):
        expr, idx = _parse_expr(tokens, idx)
        exprs.append(expr)
    return exprs


def _list_operator(expr: Expr) -> Optional[str]:
    if not isinstance(expr, ListExpr) or not expr.items:
        return None
    head = expr.items[0]
    return head.value if isinstance(head, Atom) else None


def find_deny_message_filters(sbpl_text: str) -> List[Dict[str, Any]]:
    """
    Find deny-style message filter uses inside `apply-message-filter`.

    Returns a list of records. This is a structural scan, not a semantic claim.
    """

    forms = parse_sbpl(sbpl_text)
    findings: List[Dict[str, Any]] = []

    def walk(expr: Expr, rule_action: Optional[str], rule_op: Optional[str]) -> None:
        if isinstance(expr, Atom):
            return

        op = _list_operator(expr)
        if op in {"allow", "deny"} and len(expr.items) >= 2 and isinstance(expr.items[1], Atom):
            action = op
            outer_op = expr.items[1].value
            for child in expr.items[2:]:
                walk(child, action, outer_op)
            return

        if op == "apply-message-filter":
            for child in expr.items[1:]:
                if isinstance(child, ListExpr) and _list_operator(child) == "deny" and len(child.items) >= 2 and isinstance(child.items[1], Atom):
                    findings.append(
                        {
                            "outer_action": rule_action,
                            "outer_operation": rule_op,
                            "denied_operation": child.items[1].value,
                        }
                    )
                walk(child, rule_action, rule_op)
            return

        for child in expr.items:
            walk(child, rule_action, rule_op)

    for form in forms:
        walk(form, None, None)

    return findings


def classify_enterability_for_harness_identity(sbpl_text: str) -> Dict[str, Any]:
    """
    Return a conservative, operational classification for this world.

    If the deny-message-filter signature is present, treat the profile as
    "likely apply-gated for harness identity" on this host baseline.
    """

    findings = find_deny_message_filters(sbpl_text)
    if findings:
        return {
            "classification": "likely_apply_gated_for_harness_identity",
            "signature": "deny_message_filter",
            "findings": findings,
        }
    return {
        "classification": "no_known_apply_gate_signature",
        "signature": None,
        "findings": [],
    }

