import importlib.util
from pathlib import Path
import sys


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
TOOL = ROOT / "book" / "tools" / "preflight" / "gate_minimizer.py"


def _load_tool_module():
    spec = importlib.util.spec_from_file_location("gate_minimizer", TOOL)
    assert spec and spec.loader, "failed to load gate_minimizer module spec"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_gate_minimizer_parse_and_ddmin_contract():
    mod = _load_tool_module()
    text = r'''
    ; leading comment
    (version 1)
    (allow file-read* (literal "/tmp/foo")) ; inline comment
    #| block
       comment |#
    (deny file-write* (regex #"^/tmp/.*"))
    '''
    forms = mod.parse_sbpl(text)
    rendered = mod.render_sbpl(forms)
    # Comments removed, but structure preserved.
    assert "(version 1)" in rendered
    assert '(allow file-read* (literal "/tmp/foo"))' in rendered
    assert '(deny file-write* (regex #"^/tmp/.*"))' in rendered

    # Fails iff it contains "C" (and at least one element remains).
    def pred(xs):
        return mod.CandidateClass.GATE if ("C" in xs) and len(xs) >= 1 else mod.CandidateClass.NOT_GATE

    start = ["A", "B", "C", "D", "E"]
    out = mod.ddmin(start, pred)
    assert out == ["C"]
