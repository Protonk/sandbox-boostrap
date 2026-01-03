from __future__ import annotations

from book.integration.tests import inventory_graph_helpers as helpers


def test_inventory_graph_evidence_matches_expected():
    expected = helpers.artifacts_by_kind(helpers.build_expected_graph(), ["evidence"])
    current = helpers.artifacts_by_kind(helpers.load_current_graph(), ["evidence"])
    missing, extra = helpers.diff_paths(expected, current)

    assert not missing and not extra, (
        "evidence inventory graph drift:\n"
        + ("\n".join(f"- missing: {path}" for path in missing) if missing else "")
        + ("\n".join(f"- extra: {path}" for path in extra) if extra else "")
    )
