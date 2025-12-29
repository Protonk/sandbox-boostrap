import json
import sys
import types
from pathlib import Path


def _install_ghidra_stubs():
    ghidra = types.ModuleType("ghidra")
    program = types.ModuleType("ghidra.program")
    model = types.ModuleType("ghidra.program.model")
    address = types.ModuleType("ghidra.program.model.address")

    class DummyAddressSet:
        def __init__(self):
            self.ranges = []

        def add(self, start, end):
            self.ranges.append((start, end))

    address.AddressSet = DummyAddressSet
    model.address = address
    program.model = model
    ghidra.program = program

    sys.modules["ghidra"] = ghidra
    sys.modules["ghidra.program"] = program
    sys.modules["ghidra.program.model"] = model
    sys.modules["ghidra.program.model.address"] = address


def test_io_utils_write_json(tmp_path):
    from book.api.ghidra.ghidra_lib import io_utils

    dest = tmp_path / "out" / "data.json"
    payload = {"alpha": 1}
    io_utils.write_json(str(dest), payload)

    text = dest.read_text()
    assert text.endswith("\n")
    assert json.loads(text) == payload


def test_block_utils_helpers():
    _install_ghidra_stubs()
    from book.api.ghidra.ghidra_lib import block_utils

    class DummyAddr:
        def __init__(self, offset):
            self._offset = offset

        def getOffset(self):
            return self._offset

    class DummyBlock:
        def __init__(self, name, start, end):
            self._name = name
            self._start = DummyAddr(start)
            self._end = DummyAddr(end)

        def getName(self):
            return self._name

        def getStart(self):
            return self._start

        def getEnd(self):
            return self._end

    class DummyMemory:
        def __init__(self, blocks):
            self._blocks = blocks

        def getBlocks(self):
            return self._blocks

    blocks = [DummyBlock("sandbox_TEXT", 0x10, 0x20), DummyBlock("other", 0x30, 0x40)]
    memory = DummyMemory(blocks)
    selected = block_utils.sandbox_blocks(memory=memory)
    assert len(selected) == 1
    assert selected[0].getName() == "sandbox_TEXT"

    aset = block_utils.block_set(selected)
    assert getattr(aset, "ranges", None) == [(selected[0].getStart(), selected[0].getEnd())]

    meta = block_utils.block_meta(selected)
    assert meta[0]["start"].startswith("0x")
    assert meta[0]["end"].startswith("0x")


def test_provenance_builds_relative_paths(tmp_path):
    from book.api.ghidra.ghidra_lib import provenance

    repo_root = tmp_path
    scripts_dir = repo_root / "book" / "api" / "ghidra" / "scripts"
    libs_dir = repo_root / "book" / "api" / "ghidra" / "ghidra_lib"
    world_dir = repo_root / "book" / "world" / "sonoma-14.4.1-23E224-arm64"

    scripts_dir.mkdir(parents=True)
    libs_dir.mkdir(parents=True)
    world_dir.mkdir(parents=True)

    (libs_dir / "__init__.py").write_text("")
    (libs_dir / "scan_utils.py").write_text("")
    (scripts_dir / "ghidra_bootstrap.py").write_text("")

    script_path = scripts_dir / "demo.py"
    script_path.write_text("print('demo')\n")
    program_path = repo_root / "bin" / "program.bin"
    program_path.parent.mkdir(parents=True)
    program_path.write_text("binary")
    (world_dir / "world.json").write_text(json.dumps({"world_id": "test-world"}))

    prov = provenance.build_provenance(
        "build",
        "profile",
        str(script_path),
        program_path=str(program_path),
        repo_root=str(repo_root),
    )

    assert prov["world_id"] == "test-world"
    assert prov["generator"]["script_path"].startswith("book/")
    assert prov["input"]["program_path"].startswith("bin/")
    assert prov["generator"]["deps"]
