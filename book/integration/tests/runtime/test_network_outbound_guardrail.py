from __future__ import annotations

from pathlib import Path


from book.api import path_utils
from book.integration.tests.runtime.runtime_bundle_helpers import load_bundle_json
ROOT = path_utils.find_repo_root(Path(__file__))
BASE = ROOT / "book" / "experiments" / "runtime-adversarial"
SB_ALLOW = BASE / "sb" / "net_outbound_allow.sb"
SB_DENY = BASE / "sb" / "net_outbound_deny.sb"
OUT_ROOT = BASE / "out"


def _load_lines(path: Path) -> list[str]:
    return [
        ln.strip()
        for ln in path.read_text().splitlines()
        if ln.strip() and not ln.strip().startswith(";;")
    ]


def test_net_outbound_profiles_shape():
    allow_lines = _load_lines(SB_ALLOW)
    deny_lines = _load_lines(SB_DENY)
    allow_net = [ln for ln in allow_lines if "network-outbound" in ln]
    deny_net = [ln for ln in deny_lines if "network-outbound" in ln]
    assert len(allow_net) == 1, "allow profile should have one network-outbound clause"
    assert not deny_net, "deny profile should not allow network-outbound"

    allow_core = sorted(ln for ln in allow_lines if "network-outbound" not in ln)
    deny_core = sorted(ln for ln in deny_lines if "network-outbound" not in ln)
    assert allow_core == deny_core, "profiles should be identical except for network-outbound rule"


def test_net_outbound_behavior():
    expected = load_bundle_json(OUT_ROOT, "expected_matrix.json")
    results = load_bundle_json(OUT_ROOT, "runtime_results.json")

    allow_probes = expected["profiles"]["adv:net_outbound_allow"]["probes"]
    deny_probes = expected["profiles"]["adv:net_outbound_deny"]["probes"]
    allow_runtime = results["adv:net_outbound_allow"]["probes"]
    deny_runtime = results["adv:net_outbound_deny"]["probes"]

    assert len(allow_probes) == len(allow_runtime)
    assert len(deny_probes) == len(deny_runtime)

    for probe in allow_runtime:
        assert probe.get("expected") == "allow"
        assert probe.get("actual") in {"allow", "deny"}
        if probe.get("actual") == "deny":
            assert probe.get("violation_summary") == "EPERM"
            assert probe.get("match") is False

    for probe in deny_runtime:
        assert probe.get("expected") == "deny"
        assert probe.get("actual") == "deny"
        assert probe.get("match") is True
