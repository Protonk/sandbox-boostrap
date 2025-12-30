import json
from pathlib import Path

import pytest

from book.api import path_utils
from book.api.runtime.contracts import models
from book.api.runtime.contracts import schema as rt_contract

ROOT = path_utils.find_repo_root(Path(__file__))


@pytest.mark.system
def test_sbpl_wrapper_built():
    wrapper = ROOT / "book" / "tools" / "sbpl" / "wrapper" / "wrapper"
    assert wrapper.exists(), "wrapper binary is missing; build with clang -o wrapper wrapper.c -lsandbox -framework Security -framework CoreFoundation"
    assert wrapper.is_file()


@pytest.mark.system
def test_sbpl_wrapper_blob_mode_emits_markers(run_cmd):
    wrapper = ROOT / "book" / "tools" / "sbpl" / "wrapper" / "wrapper"
    blob = ROOT / "book" / "experiments" / "sbpl-graph-runtime" / "out" / "allow_all.sb.bin"
    if not (wrapper.exists() and blob.exists()):
        pytest.skip("missing wrapper binary or allow_all.sb.bin fixture")
    res = run_cmd(
        [str(wrapper), "--blob", str(blob), "--preflight", "enforce", "--", "/bin/echo", "blob-test"],
        timeout=5,
        check=False,
        label="sbpl wrapper blob mode markers",
    )
    stderr_raw = res.stderr or ""
    preflight_markers = rt_contract.extract_sbpl_preflight_markers(stderr_raw)
    assert preflight_markers, "expected sbpl-preflight marker from wrapper"
    preflight = preflight_markers[0]
    assert preflight.get("stage") == "preflight"
    assert preflight.get("mode") == "blob"
    assert preflight.get("policy") == "enforce"
    assert isinstance(preflight.get("rc"), int)

    record_json = preflight.get("record_json")
    assert record_json, "sbpl-preflight marker missing record_json payload"
    record = json.loads(record_json)
    assert record.get("tool") == "book/tools/preflight"
    assert record.get("world_id") == models.WORLD_ID
    assert record.get("input_ref") == "book/experiments/sbpl-graph-runtime/out/allow_all.sb.bin"

    entitlement_markers = rt_contract.extract_entitlement_check_markers(stderr_raw)
    assert entitlement_markers, "expected entitlement-check marker from wrapper"
    entitlement = entitlement_markers[0]
    assert entitlement.get("stage") == "pre_apply"
    assert entitlement.get("entitlement") == "com.apple.private.security.message-filter"

    if preflight.get("rc") == 2:
        apply_markers = rt_contract.extract_sbpl_apply_markers(stderr_raw)
        assert not apply_markers, "apply marker should be absent when preflight blocks"
        return

    apply_markers = rt_contract.extract_sbpl_apply_markers(stderr_raw)
    assert apply_markers, "expected sbpl-apply marker from wrapper"
    apply = apply_markers[0]
    assert apply.get("stage") == "apply"
    assert apply.get("mode") == "blob"
    assert apply.get("api") == "sandbox_apply"
    assert isinstance(apply.get("rc"), int)
    if apply.get("rc") != 0:
        assert isinstance(apply.get("errno"), int)
