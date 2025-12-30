"""TypeScript hook build pipeline (headless, deterministic).

This module compiles hooks authored under `book/api/frida/hooks_ts/` into runtime
artifacts under `book/api/frida/hooks/`:
- `<hook>.js`
- `<hook>.manifest.json`

The runtime loader continues to inject the shared helper at load time
(`book/api/frida/script_assembly.py`), so compiled hooks must not bundle/import
the helper.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from book.api import path_utils
from book.api.frida import schema_validate


class TSHookBuildError(Exception):
    pass


def _sha256_bytes(blob: bytes) -> str:
    h = hashlib.sha256()
    h.update(blob)
    return h.hexdigest()


def _format_manifest_json(manifest: Dict[str, Any]) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def _run_cmd(argv: List[str], *, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        cwd=str(cwd),
        text=True,
        capture_output=True,
        check=False,
    )


def _ensure_node_toolchain(*, hooks_ts_dir: Path) -> None:
    tsc_path = hooks_ts_dir / "node_modules/.bin/tsc"
    if tsc_path.exists():
        return
    npm = shutil.which("npm")
    if not npm:
        raise TSHookBuildError("ToolMissingError: npm not found (required for TypeScript hook builds)")
    if not (hooks_ts_dir / "package-lock.json").exists():
        raise TSHookBuildError("ToolchainError: missing hooks_ts/package-lock.json (pinned toolchain required)")
    proc = _run_cmd([npm, "ci", "--ignore-scripts", "--no-audit", "--fund=false"], cwd=hooks_ts_dir)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip()
        msg = " ".join(msg.split())
        raise TSHookBuildError(f"NpmCiError: npm ci failed: {msg}")
    if not tsc_path.exists():
        raise TSHookBuildError("ToolchainError: npm ci completed but node_modules/.bin/tsc is missing")


def _compile_all(*, hooks_ts_dir: Path, out_dir: Path) -> Dict[str, Any]:
    _ensure_node_toolchain(hooks_ts_dir=hooks_ts_dir)
    tsc = hooks_ts_dir / "node_modules/.bin/tsc"
    proc = _run_cmd([str(tsc), "-p", "tsconfig.json", "--outDir", str(out_dir)], cwd=hooks_ts_dir)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip()
        msg = " ".join(msg.split())
        raise TSHookBuildError(f"TscError: tsc failed: {msg}")
    return {"ok": True}


def _load_ts_stems(hooks_ts_dir: Path) -> List[str]:
    stems = []
    for p in sorted(hooks_ts_dir.glob("*.ts")):
        if p.name.startswith("_"):
            continue
        stems.append(p.stem)
    if not stems:
        raise TSHookBuildError("NoHooksError: no *.ts hooks found under hooks_ts/")
    return stems


def build_ts_hooks(
    *,
    repo_root: Optional[Path] = None,
    force: bool = False,
    check: bool = False,
) -> Dict[str, Any]:
    """
    Build TypeScript-authored hooks into the runtime JS catalog.

    - If `check=True`, compiles into a staging directory and compares bytes
      against the runtime catalog; no writes are performed.
    - If `check=False`, writes outputs into the runtime catalog and refuses to
      overwrite existing files unless `force=True`.
    """
    root = repo_root or path_utils.find_repo_root()
    hooks_ts_dir = root / "book/api/frida/hooks_ts"
    runtime_hooks_dir = root / "book/api/frida/hooks"

    if not hooks_ts_dir.is_dir():
        raise TSHookBuildError("MissingDirError: hooks_ts directory not found")
    if not runtime_hooks_dir.is_dir():
        raise TSHookBuildError("MissingDirError: runtime hooks directory not found")

    stems = _load_ts_stems(hooks_ts_dir)

    with tempfile.TemporaryDirectory(prefix="sandboxlore_frida_ts_build.") as td:
        stage = Path(td)
        _compile_all(hooks_ts_dir=hooks_ts_dir, out_dir=stage)

        hooks_report: List[Dict[str, Any]] = []
        changes: List[str] = []

        for stem in stems:
            ts_path = hooks_ts_dir / f"{stem}.ts"
            manifest_src = hooks_ts_dir / f"{stem}.manifest.json"
            js_built = stage / f"{stem}.js"
            if not js_built.exists():
                raise TSHookBuildError(f"BuildOutputMissingError: expected {stem}.js in tsc outDir")
            if not manifest_src.exists():
                raise TSHookBuildError(f"ManifestMissingError: expected {stem}.manifest.json in hooks_ts")

            js_bytes = js_built.read_bytes()
            manifest_obj = json.loads(manifest_src.read_text())
            if not isinstance(manifest_obj, dict):
                raise TSHookBuildError("ManifestShapeError: manifest must be a JSON object")
            violations = schema_validate.validate_hook_manifest_v1(manifest_obj)
            if violations:
                raise TSHookBuildError(f"ManifestSchemaError: {stem}.manifest.json invalid: {violations}")

            manifest_text = _format_manifest_json(manifest_obj)
            manifest_bytes = manifest_text.encode("utf-8")

            dest_js = runtime_hooks_dir / f"{stem}.js"
            dest_manifest = runtime_hooks_dir / f"{stem}.manifest.json"

            dest_js_rel = path_utils.to_repo_relative(dest_js, root)
            dest_manifest_rel = path_utils.to_repo_relative(dest_manifest, root)

            entry: Dict[str, Any] = {
                "hook_name": stem,
                "ts_path": path_utils.to_repo_relative(ts_path, root),
                "manifest_src_path": path_utils.to_repo_relative(manifest_src, root),
                "built": {
                    "hook_js_sha256": _sha256_bytes(js_bytes),
                    "manifest_json_sha256": _sha256_bytes(manifest_bytes),
                },
                "dest": {
                    "hook_js": dest_js_rel,
                    "manifest_json": dest_manifest_rel,
                },
            }

            expected_script_path = f"book/api/frida/hooks/{stem}.js"
            manifest_hook = manifest_obj.get("hook")
            script_path = manifest_hook.get("script_path") if isinstance(manifest_hook, dict) else None
            if script_path != expected_script_path:
                raise TSHookBuildError(
                    f"ManifestPathError: {stem}.manifest.json hook.script_path must be {expected_script_path}"
                )

            # check/compare behavior
            if check:
                js_same = dest_js.exists() and dest_js.read_bytes() == js_bytes
                manifest_same = dest_manifest.exists() and dest_manifest.read_bytes() == manifest_bytes
                if not js_same:
                    changes.append(dest_js_rel)
                if not manifest_same:
                    changes.append(dest_manifest_rel)
                entry["check"] = {"hook_js_matches": js_same, "manifest_matches": manifest_same}
            else:
                if (dest_js.exists() or dest_manifest.exists()) and not force:
                    raise TSHookBuildError(
                        f"OutputExistsError: refusing to overwrite {dest_js_rel} / {dest_manifest_rel} (use --force)"
                    )
                dest_js.write_bytes(js_bytes)
                dest_manifest.write_bytes(manifest_bytes)
                entry["write"] = {"ok": True}

            hooks_report.append(entry)

        ok = not changes if check else True
        return {
            "ok": ok,
            "mode": "check" if check else "write",
            "hooks": hooks_report,
            "changes": sorted(set(changes)),
        }

