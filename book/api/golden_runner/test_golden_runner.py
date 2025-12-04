from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import book.api.golden_runner as gr


def test_ensure_tmp_files_custom_root(tmp_path: Path):
    gr.ensure_tmp_files(tmp_path)
    assert (tmp_path / "foo").read_text().startswith("runtime-checks foo")
    assert (tmp_path / "foo.txt").read_text().strip() == "foo"
    assert (tmp_path / "baz.txt").read_text().strip() == "baz"
    assert (tmp_path / "sbpl_rt" / "param_root" / "foo").exists()


def test_prepare_runtime_profile_appends_shims(tmp_path: Path):
    base = tmp_path / "base.sb"
    base.write_text("(version 1)\n(allow default)\n")
    rt_dir = tmp_path / "rt"
    shim = ["(allow shim)"]
    key_rules = {"profile:key": ["(allow key-rule)"]}
    runtime_path = gr.prepare_runtime_profile(
        base,
        "profile:key",
        key_specific_rules=key_rules,
        runtime_profile_dir=rt_dir,
        shim_rules=shim,
    )
    content = runtime_path.read_text()
    assert "(allow default)" in content
    assert "(allow shim)" in content
    assert "(allow key-rule)" in content


def test_prepare_runtime_profile_bin_passthrough(tmp_path: Path):
    bin_path = tmp_path / "p.bin"
    bin_path.write_bytes(b"\x00\x01")
    out = gr.prepare_runtime_profile(
        bin_path,
        "bin:key",
        key_specific_rules={},
        runtime_profile_dir=tmp_path / "rt",
    )
    assert out == bin_path


def test_classify_status_all_match():
    probes = [{"match": True}, {"match": True}]
    status, note = gr.classify_status(probes)
    assert status == "ok"
    assert note is None
