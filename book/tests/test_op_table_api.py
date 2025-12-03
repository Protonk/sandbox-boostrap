import json
import subprocess
from pathlib import Path

import pytest

from book.api import op_table

ROOT = Path(__file__).resolve().parents[2]
SAMPLE_SB = ROOT / "book" / "experiments" / "op-table-operation" / "sb" / "v1_read.sb"
OPS_VOCAB = ROOT / "book" / "graph" / "mappings" / "vocab" / "ops.json"
FILTERS_VOCAB = ROOT / "book" / "graph" / "mappings" / "vocab" / "filters.json"


@pytest.mark.system
def test_op_table_cli_with_compile(tmp_path):
    out = tmp_path / "summary.json"
    cmd = [
        "python3",
        "-m",
        "book.api.op_table.cli",
        str(SAMPLE_SB),
        "--compile",
        "--op-count",
        "196",
        "--json",
        str(out),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert out.exists()
    data = json.loads(out.read_text())
    assert data.get("op_entries") is not None
    assert data.get("entry_signatures") is not None


def test_build_alignment_stub():
    vocab_ops = {"ops": [{"name": "file-read*", "id": 10}], "generated_at": "test"}
    vocab_filters = {"filters": [{"name": "literal", "id": 1}]}
    summary = op_table.Summary(
        name="stub",
        ops=["file-read*"],
        filters=["literal"],
        filter_ids=[1],
        length=0,
        format_variant=None,
        op_count=1,
        op_count_source="header",
        op_entries=[4],
        section_lengths={},
        tag_counts_stride12={},
        remainder_stride12_hex="",
        literal_strings=[],
        decoder={},
        entry_signatures={},
    )
    alignment = op_table.build_alignment([summary], vocab_ops, vocab_filters)
    assert alignment["records"][0]["operation_ids"] == [10]
    assert alignment["records"][0]["filter_ids"] == [1]
