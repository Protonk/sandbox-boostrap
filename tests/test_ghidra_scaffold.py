import os
from pathlib import Path
import unittest

from dumps.ghidra import scaffold


class ScaffoldCommandTests(unittest.TestCase):
    def setUp(self):
        self.build = scaffold.BuildPaths(
            build_id="unit",
            base=Path("/tmp/unit_base"),
            kernel=Path("/tmp/unit_base/kernel.kc"),
            userland=Path("/tmp/unit_base/userland.dylib"),
            profiles_dir=Path("/tmp/unit_base/profiles"),
            compiled_textedit=Path("/tmp/unit_base/compiled.sb.bin"),
            system_version=Path("/tmp/unit_base/SYSTEM_VERSION.txt"),
        )

    def test_build_headless_command_appends_script_args(self):
        task = scaffold.TASKS["kernel-string-refs"]
        cmd, out_dir = scaffold.build_headless_command(
            task,
            self.build,
            "/opt/ghidra/headless",
            Path("/usr/bin/java"),
            no_analysis=True,
            script_args=["all", "symsub=match"],
            processor=None,
            project_name="unit_project",
        )
        self.assertIn("-noanalysis", cmd)
        self.assertIn("-import", cmd)
        self.assertEqual(str(out_dir), str(scaffold.OUT_ROOT / self.build.build_id / task.name))
        import_idx = cmd.index("-import")
        self.assertEqual(cmd[import_idx + 1], str(self.build.kernel))
        all_idx = cmd.index("all")
        vm_idx = cmd.index("-vmPath")
        self.assertLess(all_idx, vm_idx)
        self.assertEqual(cmd[all_idx + 1], "symsub=match")
        self.assertEqual(cmd[vm_idx + 1], "/usr/bin/java")

    def test_build_process_command_uses_process_flag(self):
        task = scaffold.TASKS["kernel-tag-switch"]
        cmd, _ = scaffold.build_process_command(
            task,
            self.build,
            "/opt/ghidra/headless",
            vm_path=None,
            no_analysis=False,
            script_args=[],
            project_name="unit_project",
        )
        self.assertIn("-process", cmd)
        self.assertNotIn("-import", cmd)
        proc_idx = cmd.index("-process")
        self.assertEqual(cmd[proc_idx + 1], self.build.kernel.name)
        self.assertIn("-postScript", cmd)
        self.assertIn(task.script, cmd)

    def test_resolve_headless_prefers_env(self):
        env_path = "/tmp/env_headless_bin"
        prev = os.environ.get("GHIDRA_HEADLESS")
        os.environ["GHIDRA_HEADLESS"] = env_path
        try:
            resolved = scaffold.resolve_headless_path(None, require_exists=False)
            self.assertEqual(str(resolved), env_path)
        finally:
            if prev is None:
                os.environ.pop("GHIDRA_HEADLESS", None)
            else:
                os.environ["GHIDRA_HEADLESS"] = prev
        # If the environment still carries GHIDRA_HEADLESS (CI/host), we do not expect the placeholder.
        if os.environ.get("GHIDRA_HEADLESS"):
            placeholder = scaffold.resolve_headless_path(None, require_exists=False)
            self.assertNotEqual(str(placeholder), "<ghidra-headless>")
        else:
            placeholder = scaffold.resolve_headless_path(None, require_exists=False)
            self.assertEqual(str(placeholder), "<ghidra-headless>")

    def test_ensure_under_rejects_outside(self):
        child = Path("/tmp/child")
        parent = Path("/opt/parent")
        with self.assertRaises(ValueError):
            scaffold.ensure_under(child, parent)


if __name__ == "__main__":
    unittest.main()
