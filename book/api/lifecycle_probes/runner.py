"""
Lifecycle probe runner that emits validation IR.

Outputs are intentionally small and stable; promotion into mapping-grade runtime
artifacts happens via `book/graph/mappings/runtime/generate_lifecycle.py`.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from book.api.path_utils import ensure_absolute, find_repo_root, relativize_command, to_repo_relative


DEFAULT_LIFECYCLE_OUT_DIR = Path("book/graph/concepts/validation/out/lifecycle")
DEFAULT_ENTITLEMENTS_OUT = DEFAULT_LIFECYCLE_OUT_DIR / "entitlements.json"
DEFAULT_EXTENSIONS_OUT = DEFAULT_LIFECYCLE_OUT_DIR / "extensions_dynamic.md"
DEFAULT_BUILD_DIR = Path("book/api/lifecycle_probes/build")

ENTITLEMENTS_SRC = Path("book/api/lifecycle_probes/c/entitlements_example.c")
EXTENSIONS_SRC = Path("book/api/lifecycle_probes/c/extensions_demo.c")


@dataclass(frozen=True)
class BuildSpec:
    src: Path
    out: Path
    clang_args: list[str]


def _load_world_id(repo_root: Path) -> str:
    baseline = repo_root / "book/world/sonoma-14.4.1-23E224-arm64/world.json"
    try:
        doc = json.loads(baseline.read_text())
        return str(doc.get("world_id") or "")
    except Exception:
        return ""


def _run(cmd: list[str], *, repo_root: Path, timeout_s: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=repo_root,
    )


def _build(spec: BuildSpec, *, repo_root: Path) -> None:
    spec.out.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["clang", "-Wall", "-Wextra", *spec.clang_args, str(spec.src), "-o", str(spec.out)]
    res = _run(cmd, repo_root=repo_root, timeout_s=60)
    if res.returncode != 0:
        raise RuntimeError(f"clang failed (rc={res.returncode}):\n{res.stderr.strip()}")


def _entitlements_build_spec(repo_root: Path) -> BuildSpec:
    src = ensure_absolute(ENTITLEMENTS_SRC, repo_root)
    out = ensure_absolute(DEFAULT_BUILD_DIR / "entitlements_example", repo_root)
    return BuildSpec(
        src=src,
        out=out,
        clang_args=["-framework", "Security", "-framework", "CoreFoundation"],
    )


def _extensions_build_spec(repo_root: Path) -> BuildSpec:
    src = ensure_absolute(EXTENSIONS_SRC, repo_root)
    out = ensure_absolute(DEFAULT_BUILD_DIR / "extensions_demo", repo_root)
    # `dlopen`/`dlsym` live in libSystem on macOS; `-ldl` is kept for parity with
    # the historical demo compile line and is harmless on this host baseline.
    return BuildSpec(src=src, out=out, clang_args=["-ldl"])


def capture_entitlements_evolution(out_path: Path, *, repo_root: Path | None = None, build: bool = True) -> Dict[str, Any]:
    repo_root = repo_root or find_repo_root()
    out_path = ensure_absolute(out_path, repo_root)
    spec = _entitlements_build_spec(repo_root)
    if build:
        _build(spec, repo_root=repo_root)

    res = _run([str(spec.out), "--json"], repo_root=repo_root, timeout_s=10)
    if res.returncode != 0:
        raise RuntimeError(f"entitlements probe failed (rc={res.returncode}):\n{res.stderr.strip()}")

    payload = json.loads(res.stdout)
    exe_raw = payload.get("executable")
    if isinstance(exe_raw, str) and exe_raw:
        payload["executable"] = to_repo_relative(exe_raw, repo_root)
    else:
        payload["executable"] = to_repo_relative(spec.out, repo_root)

    ent_present = payload.get("entitlements_present")
    if ent_present is False:
        payload["notes"] = "Unsigned/unsandboxed build; rerun with signed binaries to compare entitlement payloads."
    elif ent_present is True:
        payload["notes"] = "Signed build (entitlements present); compare against other signatures/entitlement payloads."
    else:
        payload["notes"] = "Probe did not report entitlements_present."

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return payload


def _format_exit(res: subprocess.CompletedProcess[str]) -> str:
    rc = res.returncode
    if rc < 0:
        return f"signal {-rc}"
    return f"exit {rc}"


def capture_extensions_dynamic(out_path: Path, *, repo_root: Path | None = None, build: bool = True) -> Dict[str, Any]:
    repo_root = repo_root or find_repo_root()
    out_path = ensure_absolute(out_path, repo_root)
    spec = _extensions_build_spec(repo_root)
    if build:
        _build(spec, repo_root=repo_root)

    res = _run([str(spec.out)], repo_root=repo_root, timeout_s=10)
    token_issued = "Issued extension token:" in (res.stdout or "")
    status = "ok" if token_issued and res.returncode == 0 else "blocked"

    world_id = _load_world_id(repo_root)
    ts = datetime.now(timezone.utc).isoformat()
    cmd_rel = relativize_command([spec.out], repo_root)
    header_lines = [
        "# extensions-dynamic probe notes",
        "",
        f"- world_id: {world_id}",
        f"- executable: {to_repo_relative(spec.out, repo_root)}",
        f"- command: {' '.join(cmd_rel)}",
        f"- result: {status} ({_format_exit(res)}), token_issued={str(token_issued).lower()}",
    ]

    details = [
        "",
        f"- captured_at: {ts}",
        "",
        "## stdout",
        "```text",
        (res.stdout or "").rstrip(),
        "```",
        "",
        "## stderr",
        "```text",
        (res.stderr or "").rstrip(),
        "```",
        "",
    ]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(header_lines + details))

    return {
        "status": status,
        "token_issued": token_issued,
        "exit": _format_exit(res),
        "executable": to_repo_relative(spec.out, repo_root),
        "command": cmd_rel,
        "out_path": to_repo_relative(out_path, repo_root),
    }


def write_validation_out(*, repo_root: Path | None = None) -> None:
    repo_root = repo_root or find_repo_root()
    ent_path = ensure_absolute(DEFAULT_ENTITLEMENTS_OUT, repo_root)
    ext_path = ensure_absolute(DEFAULT_EXTENSIONS_OUT, repo_root)
    capture_entitlements_evolution(ent_path, repo_root=repo_root, build=True)
    capture_extensions_dynamic(ext_path, repo_root=repo_root, build=True)
    print(f"[+] wrote {to_repo_relative(ent_path, repo_root)}")
    print(f"[+] wrote {to_repo_relative(ext_path, repo_root)}")

