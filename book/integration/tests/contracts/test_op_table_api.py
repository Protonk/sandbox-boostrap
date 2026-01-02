import json
import sys
from pathlib import Path

import pytest

from book.api import profile as pt

from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
SAMPLE_SB = (
    ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "profile-pipeline"
    / "op-table-operation"
    / "sb"
    / "v1_read.sb"
)
OPS_VOCAB = ROOT / "book" / "evidence" / "graph" / "mappings" / "vocab" / "ops.json"
FILTERS_VOCAB = ROOT / "book" / "evidence" / "graph" / "mappings" / "vocab" / "filters.json"


@pytest.mark.system
def test_op_table_cli_with_compile(tmp_path, run_cmd):
    out = tmp_path / "summary.json"
    cmd = [
        sys.executable,
        "-m",
        "book.api.profile.cli",
        "op-table",
        str(SAMPLE_SB),
        "--compile",
        "--op-count",
        "196",
        "--out",
        str(out),
    ]
    run_cmd(cmd, check=True, label="op-table cli")
    assert out.exists()
    data = json.loads(out.read_text())
    assert data.get("op_entries") is not None
    assert data.get("entry_signatures") is not None


def test_build_alignment_stub():
    vocab_ops = {"ops": [{"name": "file-read*", "id": 10}]}
    vocab_filters = {"filters": [{"name": "literal", "id": 1}]}
    summary = pt.op_table.Summary(
        name="stub",
        ops=["file-read*"],
        filters=["literal"],
        filter_ids=[1],
        length=0,
        format_variant=None,
        op_count=1,
        op_count_source="header",
        header_words=None,
        op_entries=[4],
        section_lengths={},
        tag_counts_stride12={},
        remainder_stride12_hex="",
        literal_strings=[],
        decoder={},
        entry_signatures={},
    )
    alignment = pt.op_table.build_alignment([summary], vocab_ops, vocab_filters)
    assert alignment["records"][0]["operation_ids"] == [10]
    assert alignment["records"][0]["filter_ids"] == [1]
