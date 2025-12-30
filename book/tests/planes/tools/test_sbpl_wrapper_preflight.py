from __future__ import annotations

from pathlib import Path

import pytest

from book.api.runtime.contracts import schema as rt_contract


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
WRAPPER = ROOT / "book" / "tools" / "sbpl" / "wrapper" / "wrapper"


@pytest.mark.system
def test_sbpl_wrapper_preflight_blocks_known_apply_gate_signature(tmp_path: Path, run_cmd):
    if not WRAPPER.exists():
        pytest.skip("wrapper binary missing")

    sbpl_path = tmp_path / "gated.sb"
    sbpl_path.write_text('(version 2)\n(allow mach-bootstrap (apply-message-filter (deny mach-message-send)))\n')

    res = run_cmd(
        [str(WRAPPER), "--sbpl", str(sbpl_path), "--", "/usr/bin/true"],
        timeout=10,
        check=False,
        label="sbpl wrapper preflight",
    )

    stderr_raw = res.stderr or ""
    preflight_markers = rt_contract.extract_sbpl_preflight_markers(stderr_raw)
    if not preflight_markers:
        pytest.skip("wrapper did not emit sbpl-preflight marker (preflight unavailable)")

    assert res.returncode == 2
    assert len(preflight_markers) == 1
    marker = preflight_markers[0]
    assert marker.get("stage") == "preflight"
    assert marker.get("policy") == "enforce"
    assert marker.get("rc") == 2

    assert rt_contract.extract_sbpl_apply_markers(stderr_raw) == []
