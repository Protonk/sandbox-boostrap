import json
from pathlib import Path


def test_kernel_import_census_empty():
    base = Path("book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-imports")
    all_path = base / "imports_all.json"
    filt_path = base / "imports_filtered_sandbox.json"
    assert all_path.exists(), "imports_all.json missing; rerun kernel-imports task"
    assert filt_path.exists(), "imports_filtered_sandbox.json missing; rerun filter_imports.py"

    all_data = json.loads(all_path.read_text())
    filt_data = json.loads(filt_path.read_text())

    assert all_data.get("meta", {}).get("symbol_count", -1) == 0
    assert len(all_data.get("symbols", [])) == 0
    assert filt_data.get("meta", {}).get("filtered_count", -1) == 0
    assert len(filt_data.get("symbols", [])) == 0
