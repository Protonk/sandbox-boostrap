from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from book.api.runtime_tools.core import contract as rt_contract


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "book" / "tools" / "sbpl" / "wrapper" / "wrapper"


def test_sbpl_wrapper_preflight_blocks_known_apply_gate_signature(tmp_path: Path):
    if not WRAPPER.exists():
        pytest.skip("wrapper binary missing")

    sbpl_path = tmp_path / "gated.sb"
    sbpl_path.write_text('(version 2)\n(allow mach-bootstrap (apply-message-filter (deny mach-message-send)))\n')

    res = subprocess.run(
        [str(WRAPPER), "--sbpl", str(sbpl_path), "--", "/usr/bin/true"],
        capture_output=True,
        text=True,
        timeout=10,
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
