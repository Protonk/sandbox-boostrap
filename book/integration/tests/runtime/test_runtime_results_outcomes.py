import json
from pathlib import Path


from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
RUNTIME_IR = (
    ROOT
    / "book"
    / "evidence"
    / "graph"
    / "concepts"
    / "validation"
    / "out"
    / "experiments"
    / "runtime-checks"
    / "runtime_results.normalized.json"
)
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

def test_runtime_results_golden_profiles_have_expected_outcomes():
    events, matrix = _load_ir()

    failures: list[str] = []

    missing_matrix = sorted(GOLDEN - set(matrix.keys()))
    if missing_matrix:
        failures.append(f"golden profiles missing from expected_matrix: {missing_matrix}")

    present = {e.get("profile_id") for e in events}
    missing_results = sorted(GOLDEN - present)
    if missing_results:
        failures.append(f"golden profiles missing from runtime_results: {missing_results}")

    if failures:
        raise AssertionError("\n".join(failures))

    def _check(label: str, fn) -> None:
        try:
            fn()
        except AssertionError as exc:
            failures.append(f"{label}: {exc}")

    def check_bucket_profiles():
        bucket4 = _probe_map(events, "bucket4:v1_read")
        bucket5 = _probe_map(events, "bucket5:v11_read_subpath")
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

    def check_sys_bsd():
        bsd = _probe_map(events, "sys:bsd")
        if _all_blocked(bsd):
            _assert_blocked(bsd)
            return
        for name in ["read_/etc/hosts", "write_/etc/hosts", "read_/tmp/foo", "write_/tmp/foo"]:
            assert bsd[name]["actual"] == "deny"

    def check_sys_airlock():
        airlock = _probe_map(events, "sys:airlock")
        if _all_blocked(airlock):
            _assert_blocked(airlock)
            return
        for probe in airlock.values():
            assert probe["violation_summary"] == "EPERM"
            assert probe["actual"] == "deny"

    def check_metafilter_any():
        meta = _probe_map(events, "runtime:metafilter_any")
        if _all_blocked(meta):
            _assert_blocked(meta)
            return
        assert meta["read_foo"]["actual"] == "allow"
        assert meta["read_bar"]["actual"] == "allow"
        assert meta["read_other"]["actual"] == "allow"
        assert meta["read_baz"]["actual"] == "deny"
        assert meta["write_baz"]["actual"] == "deny"

    def check_strict_profile():
        strict = _probe_map(events, "runtime:strict_1")
        if _all_blocked(strict):
            _assert_blocked(strict)
            return
        assert strict["read_ok"]["actual"] == "allow"
        assert strict["write_ok"]["actual"] == "allow"
        assert strict["read_hosts"]["actual"] == "deny"
        assert strict["write_hosts"]["actual"] == "deny"

    _check("bucket profiles", check_bucket_profiles)
    _check("sys:bsd", check_sys_bsd)
    _check("sys:airlock", check_sys_airlock)
    _check("runtime:metafilter_any", check_metafilter_any)
    _check("runtime:strict_1", check_strict_profile)

    assert not failures, "\n".join(failures)
