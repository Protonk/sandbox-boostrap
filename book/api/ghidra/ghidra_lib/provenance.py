"""Provenance helpers for Ghidra outputs.

This module records script, input, and dependency hashes so canonical outputs
can prove freshness without re-running Ghidra. Keep it Python 2 compatible for
Jython.
"""

import json
import os

try:
    from ghidra_lib import scan_utils
except ImportError:
    from . import scan_utils


# Bump this only when changing semantics, and regenerate canonical outputs.
PROVENANCE_SCHEMA_VERSION = 1


def _collect_deps(repo_root, extra_deps=None):
    deps = []
    if not repo_root:
        return deps
    dep_paths = set()
    dep_paths.add(os.path.join("book", "api", "ghidra", "scripts", "ghidra_bootstrap.py"))
    ghidra_lib_dir = os.path.join(repo_root, "book", "api", "ghidra", "ghidra_lib")
    if os.path.isdir(ghidra_lib_dir):
        for root, dirs, files in os.walk(ghidra_lib_dir):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in files:
                if not name.endswith(".py"):
                    continue
                # Hash all helper modules so behavior changes are caught even if the main script doesn't change.
                dep_paths.add(os.path.join(root, name))
    if extra_deps:
        for dep in extra_deps:
            dep_paths.add(dep)
    for path in sorted(dep_paths):
        dep_abs = path if os.path.isabs(path) else os.path.join(repo_root, path)
        if not os.path.isfile(dep_abs):
            continue
        dep_rel = scan_utils.to_repo_relative(dep_abs, repo_root)
        deps.append({"path": dep_rel, "sha256": scan_utils.sha256_path(dep_abs)})
    return deps


def _read_world_id(repo_root):
    if not repo_root:
        return None
    # World ID is pinned to the Sonoma baseline; keep this path stable across refactors.
    world_path = os.path.join(repo_root, "book", "world", "sonoma-14.4.1-23E224-arm64", "world.json")
    if not os.path.isfile(world_path):
        return None
    try:
        with open(world_path, "r") as f:
            data = json.load(f)
        return data.get("world_id")
    except Exception:
        return None


def _guess_program_path(repo_root, build_id, program_name):
    if not repo_root or not build_id or not program_name:
        return None
    program_name = os.path.basename(str(program_name))
    base = os.path.join(repo_root, "dumps", "Sandbox-private", build_id)
    candidates = [
        os.path.join(base, "kernel", program_name),
        os.path.join(base, "userland", program_name),
        os.path.join(base, "profiles", program_name),
        os.path.join(base, "profiles", "compiled", program_name),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def build_provenance(
    build_id,
    profile_id,
    script_path,
    program_path=None,
    repo_root=None,
    extra_deps=None,
    program_name=None,
):
    if repo_root is None:
        repo_root = scan_utils.find_repo_root(script_path)
    if repo_root is None:
        repo_root = scan_utils.find_repo_root(os.getcwd())
    if repo_root is None:
        env_root = os.environ.get("SANDBOX_LORE_REPO_ROOT") or os.environ.get("PWD")
        if env_root and os.path.isdir(os.path.join(env_root, "book")) and os.path.isdir(os.path.join(env_root, "dumps")):
            repo_root = env_root
    script_rel = scan_utils.to_repo_relative(script_path, repo_root)
    script_sha = scan_utils.sha256_path(script_path)

    deps = _collect_deps(repo_root, extra_deps=extra_deps)

    if program_path is None:
        try:
            # Ghidra exposes the loaded binary via currentProgram; use it when running headless.
            program_path = currentProgram.getExecutablePath()
        except Exception:
            program_path = None
    if (not program_path or not os.path.isfile(program_path)) and repo_root and build_id:
        if program_name is None:
            try:
                program_name = currentProgram.getName()
            except Exception:
                program_name = None
        guessed = _guess_program_path(repo_root, build_id, program_name)
        if guessed:
            program_path = guessed
    program_sha = None
    if program_path and os.path.isfile(program_path):
        program_sha = scan_utils.sha256_path(program_path)
    program_rel = scan_utils.to_repo_relative(program_path, repo_root) if program_path else None

    return {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "world_id": _read_world_id(repo_root),
        "generator": {
            "script_path": script_rel,
            "script_content_sha256": script_sha,
            "deps": deps,
        },
        "input": {
            "program_path": program_rel,
            "program_sha256": program_sha,
        },
        "analysis": {
            "profile_id": profile_id,
        },
        "build_id": build_id,
    }
