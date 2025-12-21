import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_IR = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "experiments" / "runtime-checks" / "runtime_results.normalized.json"
GOLDEN = {
    "bucket4:v1_read",
    "bucket5:v11_read_subpath",
    "runtime:metafilter_any",
    "runtime:strict_1",
    "sys:bsd",
    "sys:airlock",
}
BLOCKED_STAGES = {"apply", "preflight", "bootstrap"}


def _load_ir():
    assert RUNTIME_IR.exists(), "missing normalized runtime IR"
    data = json.loads(RUNTIME_IR.read_text())
    return data.get("events") or [], (data.get("expected_matrix") or {}).get("profiles", {})


def _probe_map(events, profile_id):
    out = {}
    for ev in events:
        if ev.get("profile_id") != profile_id:
            continue
        name = ev.get("probe_name")
        if name:
            out[name] = ev
    return out


def _all_blocked(probes):
    blocked = [p for p in probes.values() if p.get("failure_stage") in BLOCKED_STAGES]
    if blocked:
        assert len(blocked) == len(probes), "mixed blocked/unblocked probes"
        return True
    return False


def _assert_blocked(probes):
    for probe in probes.values():
        stage = probe.get("failure_stage")
        assert stage in BLOCKED_STAGES
        assert probe.get("actual") in {None, "deny"}
        if stage == "apply":
            assert probe.get("violation_summary") == "EPERM"


def test_golden_presence():
    events, matrix = _load_ir()
    assert GOLDEN.issubset(matrix.keys()), "golden profiles missing from expected_matrix"
    present = {e.get("profile_id") for e in events}
    assert GOLDEN.issubset(present), "golden profiles missing from runtime_results"


def test_bucket_profiles_allow_deny():
    data, _ = _load_ir()
    bucket4 = _probe_map(data, "bucket4:v1_read")
    bucket5 = _probe_map(data, "bucket5:v11_read_subpath")
    blocked = _all_blocked(bucket4) or _all_blocked(bucket5)
    if blocked:
        assert _all_blocked(bucket4) and _all_blocked(bucket5)
        _assert_blocked(bucket4)
        _assert_blocked(bucket5)
        return

    assert bucket4["read_/etc/hosts"]["actual"] == "allow"
    assert bucket4["write_/etc/hosts"]["actual"] == "deny"
    assert bucket4["read_/tmp/foo"]["actual"] == "allow"

    assert bucket5["read_/tmp/foo"]["actual"] == "allow"
    assert bucket5["read_/tmp/bar"]["actual"] == "deny"
    assert bucket5["write_/tmp/foo"]["actual"] == "deny"


def test_sys_bsd_expected_denies():
    data, _ = _load_ir()
    bsd = _probe_map(data, "sys:bsd")
    if _all_blocked(bsd):
        _assert_blocked(bsd)
        return
    for name in ["read_/etc/hosts", "write_/etc/hosts", "read_/tmp/foo", "write_/tmp/foo"]:
        assert bsd[name]["actual"] == "deny"


def test_sys_airlock_expected_fail():
    data, _ = _load_ir()
    airlock = _probe_map(data, "sys:airlock")
    if _all_blocked(airlock):
        _assert_blocked(airlock)
        return
    # All probes should fail due to sandbox_init EPERM.
    for probe in airlock.values():
        assert probe["violation_summary"] == "EPERM"
        assert probe["actual"] == "deny"


def test_metafilter_any_outcomes():
    data, _ = _load_ir()
    meta = _probe_map(data, "runtime:metafilter_any")
    if _all_blocked(meta):
        _assert_blocked(meta)
        return
    assert meta["read_foo"]["actual"] == "allow"
    assert meta["read_bar"]["actual"] == "allow"
    assert meta["read_other"]["actual"] == "allow"
    assert meta["read_baz"]["actual"] == "deny"
    assert meta["write_baz"]["actual"] == "deny"


def test_strict_profile_outcomes():
    data, _ = _load_ir()
    strict = _probe_map(data, "runtime:strict_1")
    if _all_blocked(strict):
        _assert_blocked(strict)
        return
    assert strict["read_ok"]["actual"] == "allow"
    assert strict["write_ok"]["actual"] == "allow"
    assert strict["read_hosts"]["actual"] == "deny"
    assert strict["write_hosts"]["actual"] == "deny"
