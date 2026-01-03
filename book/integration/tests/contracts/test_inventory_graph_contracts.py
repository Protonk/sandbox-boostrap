from __future__ import annotations

from book.integration.tests import inventory_graph_helpers as helpers


def _contract_paths(doc: dict) -> dict:
    artifacts = doc.get("artifacts") or []
    out: dict = {}
    for entry in artifacts:
        if not isinstance(entry, dict):
            continue
        if entry.get("sensitivity") == "contract" and entry.get("path"):
            out[str(entry["path"])] = entry
    return out


def test_inventory_graph_contracts_tracked():
    expected = _contract_paths(helpers.build_expected_graph())
    current = _contract_paths(helpers.load_current_graph())
    missing, extra = helpers.diff_paths(expected, current)

    assert not missing and not extra, (
        "contract inventory graph drift:\n"
        + ("\n".join(f"- missing: {path}" for path in missing) if missing else "")
        + ("\n".join(f"- extra: {path}" for path in extra) if extra else "")
    )
