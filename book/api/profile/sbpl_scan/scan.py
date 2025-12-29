"""
SBPL scanners for host-specific, operational constraints.

These scanners are intentionally conservative and structural: they exist to
avoid "dead-end" runtime probe plans where a profile cannot be applied by the
current harness identity on this world.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .model import Atom, Expr, ListExpr
from .parser import list_operator, parse_sbpl


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

        op = list_operator(expr)
        if op in {"allow", "deny"} and len(expr.items) >= 2 and isinstance(expr.items[1], Atom):
            action = op
            outer_op = expr.items[1].value
            for child in expr.items[2:]:
                walk(child, action, outer_op)
            return

        if op == "apply-message-filter":
            for child in expr.items[1:]:
                if (
                    isinstance(child, ListExpr)
                    and list_operator(child) == "deny"
                    and len(child.items) >= 2
                    and isinstance(child.items[1], Atom)
                ):
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
