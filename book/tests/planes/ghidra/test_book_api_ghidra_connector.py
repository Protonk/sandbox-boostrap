import tempfile
from pathlib import Path

import pytest

from book.api.ghidra import connector
from book.api.ghidra import scaffold


def _stub_build(tmp_dir: Path, build_id: str = "unit") -> scaffold.BuildPaths:
    kernel = tmp_dir / "kernel.kc"
    kernel_collection = tmp_dir / "kernel_collection.kc"
    sandbox_kext = tmp_dir / "sandbox.kext"
    amfi_kext = tmp_dir / "amfi.kext"
    userland = tmp_dir / "userland.dylib"
    profiles = tmp_dir / "profiles"
    compiled = tmp_dir / "compiled.sb.bin"
    system_version = tmp_dir / "SYSTEM_VERSION.txt"
    profiles.mkdir(parents=True, exist_ok=True)
    for path in [kernel, kernel_collection, sandbox_kext, amfi_kext, userland, compiled, system_version]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    return scaffold.BuildPaths(
        build_id=build_id,
        base=tmp_dir,
        kernel=kernel,
        kernel_collection=kernel_collection,
        sandbox_kext=sandbox_kext,
        amfi_kext=amfi_kext,
        userland=userland,
        profiles_dir=profiles,
        compiled_textedit=compiled,
        system_version=system_version,
    )


def test_registry_default_includes_kernel_symbols():
    registry = connector.TaskRegistry.default()
    tasks = registry.list()
    assert "kernel-symbols" in tasks
    spec = registry.get("kernel-symbols")
    assert spec.script_path.name == "kernel_symbols.py"
    assert "symbols" in spec.description.lower()


def test_build_invocation_uses_stub_paths(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        stub = _stub_build(Path(tmp))
        monkeypatch.setattr(scaffold.BuildPaths, "from_build", classmethod(lambda cls, build_id=None: stub))
        runner = connector.HeadlessConnector(registry=connector.TaskRegistry.default(), ghidra_headless="/opt/ghidra/headless")
        invocation = runner.build(task_name="kernel-symbols", build_id=stub.build_id, no_analysis=True)
        assert "-import" in invocation.command
        import_idx = invocation.command.index("-import")
        assert invocation.command[import_idx + 1] == str(stub.kernel)
        assert invocation.mode == "import"
        assert "-Duser.home=" in invocation.env.get("JAVA_TOOL_OPTIONS", "")
        # render_shell should not raise
        shell_cmd = invocation.render_shell()
        assert "kernel-symbols" in shell_cmd


def test_process_existing_requires_project(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        build_id = "unit-ghidra-connector-missing"
        stub = _stub_build(Path(tmp), build_id=build_id)
        monkeypatch.setattr(scaffold.BuildPaths, "from_build", classmethod(lambda cls, build_id=None: stub))
        runner = connector.HeadlessConnector(registry=connector.TaskRegistry.default(), ghidra_headless="/opt/ghidra/headless")
        with pytest.raises(FileNotFoundError):
            runner.build(task_name="kernel-symbols", build_id=build_id, process_existing=True)
