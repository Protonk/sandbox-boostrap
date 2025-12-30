import io
import contextlib

from book.api.ghidra import cli


def _run_cli(args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli.main(args)
    return code, buf.getvalue()


def test_cli_groups_lists_expected_groups():
    code, out = _run_cli(["groups"])
    assert code == 0
    groups = {line.strip() for line in out.splitlines() if line.strip()}
    for expected in {"symbols", "imports", "disasm", "scan", "xref", "policy", "data"}:
        assert expected in groups


def test_cli_list_group_symbols_contains_kernel_symbols():
    code, out = _run_cli(["list", "--group", "symbols"])
    assert code == 0
    assert "kernel-symbols" in out


def test_cli_describe_kernel_symbols():
    code, out = _run_cli(["describe", "kernel-symbols"])
    assert code == 0
    assert "name: kernel-symbols" in out
    assert "import_target:" in out
