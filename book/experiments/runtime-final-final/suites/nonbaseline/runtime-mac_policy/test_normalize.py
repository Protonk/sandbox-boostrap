import importlib.util
import json
from pathlib import Path


def _load_normalize():
    here = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("runtime_mac_policy.normalize", here / "normalize.py")
    if spec is None or spec.loader is None:
        raise ImportError("Failed to load normalize.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


normalize = _load_normalize()


def test_normalize_produces_schema_shaped_json(tmp_path: Path):
    raw = tmp_path / "raw.log"
    raw.write_text("EVENT target=0x100 caller=0x200 mpc=0xabc handlep=0xdef xd=0x0 slots=0x1,0x2\n")

    events = normalize.parse_raw_log(raw.read_text().splitlines())
    output = normalize.build_output(
        events=events,
        runtime_world_id="runtime-mac-policy-test",
        os_build="test-build",
        kernel_version="test-kernel",
        bootkc_uuid=None,
        bootkc_hash=None,
        sandbox_kext_uuid=None,
        sandbox_kext_hash=None,
        kaslr_slide=None,
        sip_config=None,
        tracing_config=None,
        static_refs={"op_table_hash": "hash-op", "vocab_ops_hash": "hash-ops", "vocab_filters_hash": "hash-filters"},
    )

    out_path = tmp_path / "out.json"
    out_path.write_text(json.dumps(output))
    data = json.loads(out_path.read_text())

    assert data["runtime_world_id"] == "runtime-mac-policy-test"
    assert data["static_reference"]["op_table_hash"] == "hash-op"
    assert len(data["events"]) == 1
    event = data["events"][0]
    assert event["args"]["mpc"] == "0xabc"
    assert event["mpc_raw_slots"] == ["0x1", "0x2"]


def test_parse_target_symbol_lines(tmp_path: Path):
    raw = tmp_path / "raw_symbol.log"
    raw.write_text("EVENT target_symbol=vnode_put mpc=ffff handlep=abcd xd=0\n")

    events = normalize.parse_raw_log(raw.read_text().splitlines())
    assert len(events) == 1
    event = events[0]
    assert event["target_symbol"] == "vnode_put"
    assert event["args"]["mpc"] == "ffff"
    assert event["args"]["handlep"] == "abcd"
