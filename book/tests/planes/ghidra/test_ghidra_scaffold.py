import os
from pathlib import Path

from book.api.ghidra import scaffold


def _build_paths() -> scaffold.BuildPaths:
    return scaffold.BuildPaths(
        build_id="unit",
        base=Path("/tmp/unit_base"),
        kernel=Path("/tmp/unit_base/kernel.kc"),
        kernel_collection=Path("/tmp/unit_base/kernel_collection.kc"),
        sandbox_kext=Path("/tmp/unit_base/sandbox.kext"),
        amfi_kext=Path("/tmp/unit_base/amfi.kext"),
        userland=Path("/tmp/unit_base/userland.dylib"),
        profiles_dir=Path("/tmp/unit_base/profiles"),
        compiled_textedit=Path("/tmp/unit_base/compiled.sb.bin"),
        system_version=Path("/tmp/unit_base/SYSTEM_VERSION.txt"),
    )


def test_build_headless_command_appends_script_args():
    build = _build_paths()
    task = scaffold.TASKS["kernel-string-refs"]
    cmd, out_dir = scaffold.build_headless_command(
        task,
        build,
        "/opt/ghidra/headless",
        Path("/usr/bin/java"),
        no_analysis=True,
        script_args=["all", "symsub=match"],
        processor=None,
        analysis_properties=None,
        pre_scripts=[],
        project_name="unit_project",
    )
    assert "-noanalysis" in cmd
    assert "-import" in cmd
    assert str(out_dir) == str(scaffold.OUT_ROOT / build.build_id / task.name)
    import_idx = cmd.index("-import")
    assert cmd[import_idx + 1] == str(build.kernel)
    all_idx = cmd.index("all")
    vm_idx = cmd.index("-vmPath")
    assert all_idx > vm_idx
    assert cmd[vm_idx + 1] == "/usr/bin/java"
    # Script args should appear at the tail in the order provided.
    assert cmd[all_idx + 1] == "symsub=match"
    assert cmd[-2:] == ["all", "symsub=match"]


def test_build_process_command_uses_process_flag():
    build = _build_paths()
    task = scaffold.TASKS["kernel-tag-switch"]
    cmd, _ = scaffold.build_process_command(
        task,
        build,
        "/opt/ghidra/headless",
        vm_path=None,
        no_analysis=False,
        script_args=[],
        analysis_properties=None,
        pre_scripts=[],
        project_name="unit_project",
    )
    assert "-process" in cmd
    assert "-import" not in cmd
    proc_idx = cmd.index("-process")
    assert cmd[proc_idx + 1] == build.kernel.name
    assert "-postScript" in cmd
    assert task.script in cmd


def test_resolve_headless_prefers_env():
    env_path = "/tmp/env_headless_bin"
    prev = os.environ.get("GHIDRA_HEADLESS")
    os.environ["GHIDRA_HEADLESS"] = env_path
    try:
        resolved = scaffold.resolve_headless_path(None, require_exists=False)
        assert str(resolved) == env_path
    finally:
        if prev is None:
            os.environ.pop("GHIDRA_HEADLESS", None)
        else:
            os.environ["GHIDRA_HEADLESS"] = prev
    # If the environment still carries GHIDRA_HEADLESS (CI/host), we do not expect the placeholder.
    if os.environ.get("GHIDRA_HEADLESS"):
        placeholder = scaffold.resolve_headless_path(None, require_exists=False)
        assert str(placeholder) != "<ghidra-headless>"
    else:
        placeholder = scaffold.resolve_headless_path(None, require_exists=False)
        assert str(placeholder) == "<ghidra-headless>"


def test_ensure_under_rejects_outside():
    child = Path("/tmp/child")
    parent = Path("/opt/parent")
    try:
        scaffold.ensure_under(child, parent)
    except ValueError:
        return
    raise AssertionError("expected ensure_under to reject child outside parent")
