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
from typing import Any, Dict, List

from book.api.path_utils import ensure_absolute, find_repo_root, relativize_command, to_repo_relative
from book.api.runtime.contracts import schema as rt_contract


DEFAULT_LIFECYCLE_OUT_DIR = Path("book/evidence/graph/concepts/validation/out/lifecycle")
DEFAULT_ENTITLEMENTS_OUT = DEFAULT_LIFECYCLE_OUT_DIR / "entitlements.json"
DEFAULT_EXTENSIONS_OUT = DEFAULT_LIFECYCLE_OUT_DIR / "extensions_dynamic.md"
DEFAULT_PLATFORM_OUT = DEFAULT_LIFECYCLE_OUT_DIR / "platform.jsonl"
DEFAULT_CONTAINERS_OUT = DEFAULT_LIFECYCLE_OUT_DIR / "containers.json"
DEFAULT_APPLY_ATTEMPT_OUT = DEFAULT_LIFECYCLE_OUT_DIR / "apply_attempt.json"
DEFAULT_BUILD_DIR = Path("book/api/lifecycle/build")
DEFAULT_APPLY_ATTEMPT_SBPL = DEFAULT_BUILD_DIR / "apply_attempt_default.sb"

ENTITLEMENTS_SRC = Path("book/api/lifecycle/c/entitlements_example.c")
EXTENSIONS_SRC = Path("book/api/lifecycle/c/extensions_demo.c")
PLATFORM_POLICY_SRC = Path("book/api/lifecycle/c/platform_policy.c")
CONTAINERS_SRC = Path("book/api/lifecycle/swift/containers_demo.swift")


@dataclass(frozen=True)
class BuildSpec:
    src: Path
    out: Path
    clang_args: list[str]


@dataclass(frozen=True)
class SwiftBuildSpec:
    src: Path
    out: Path
    swiftc_args: list[str]


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


def _build_swift(spec: SwiftBuildSpec, *, repo_root: Path) -> None:
    spec.out.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["swiftc", *spec.swiftc_args, str(spec.src), "-o", str(spec.out)]
    res = _run(cmd, repo_root=repo_root, timeout_s=60)
    if res.returncode != 0:
        raise RuntimeError(f"swiftc failed (rc={res.returncode}):\n{res.stderr.strip()}")


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


def _platform_policy_build_spec(repo_root: Path) -> BuildSpec:
    src = ensure_absolute(PLATFORM_POLICY_SRC, repo_root)
    out = ensure_absolute(DEFAULT_BUILD_DIR / "platform_policy", repo_root)
    return BuildSpec(src=src, out=out, clang_args=["-framework", "CoreServices"])


def _containers_build_spec(repo_root: Path) -> SwiftBuildSpec:
    src = ensure_absolute(CONTAINERS_SRC, repo_root)
    out = ensure_absolute(DEFAULT_BUILD_DIR / "containers_demo", repo_root)
    return SwiftBuildSpec(src=src, out=out, swiftc_args=[])


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

    world_id = _load_world_id(repo_root)
    payload["world_id"] = world_id
    payload["captured_at"] = datetime.now(timezone.utc).isoformat()
    payload["command"] = relativize_command([spec.out, "--json"], repo_root)

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


def capture_platform_policy(out_path: Path, *, repo_root: Path | None = None, build: bool = True) -> Dict[str, Any]:
    repo_root = repo_root or find_repo_root()
    out_path = ensure_absolute(out_path, repo_root)
    spec = _platform_policy_build_spec(repo_root)
    if build:
        _build(spec, repo_root=repo_root)

    cmd = [str(spec.out), "--jsonl"]
    res = _run(cmd, repo_root=repo_root, timeout_s=10)
    if res.returncode != 0:
        raise RuntimeError(f"platform-policy probe failed (rc={res.returncode}):\n{res.stderr.strip()}")

    events: List[Dict[str, Any]] = []
    for raw_line in (res.stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        events.append(json.loads(line))

    world_id = _load_world_id(repo_root)
    ts = datetime.now(timezone.utc).isoformat()
    meta = {
        "kind": "platform-policy",
        "world_id": world_id,
        "captured_at": ts,
        "executable": to_repo_relative(spec.out, repo_root),
        "command": relativize_command(cmd, repo_root),
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(meta, sort_keys=True)]
    lines.extend(json.dumps(e, sort_keys=True) for e in events)
    out_path.write_text("\n".join(lines) + "\n")
    return {"status": "ok", "event_count": len(events), "out_path": to_repo_relative(out_path, repo_root)}


def capture_containers(out_path: Path, *, repo_root: Path | None = None, build: bool = True) -> Dict[str, Any]:
    repo_root = repo_root or find_repo_root()
    out_path = ensure_absolute(out_path, repo_root)
    spec = _containers_build_spec(repo_root)
    if build:
        _build_swift(spec, repo_root=repo_root)

    cmd = [str(spec.out), "--json"]
    res = _run(cmd, repo_root=repo_root, timeout_s=10)
    if res.returncode != 0:
        raise RuntimeError(f"containers probe failed (rc={res.returncode}):\n{res.stderr.strip()}")

    payload = json.loads(res.stdout)
    payload["world_id"] = _load_world_id(repo_root)
    payload["captured_at"] = datetime.now(timezone.utc).isoformat()
    payload["executable"] = to_repo_relative(spec.out, repo_root)
    payload["command"] = relativize_command(cmd, repo_root)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return {"status": "ok", "out_path": to_repo_relative(out_path, repo_root)}


def capture_apply_attempt(
    out_path: Path,
    *,
    repo_root: Path | None = None,
    sbpl_file: Path | None = None,
    preflight_mode: str = "enforce",
) -> Dict[str, Any]:
    repo_root = repo_root or find_repo_root()
    out_path = ensure_absolute(out_path, repo_root)
    if preflight_mode not in {"enforce", "off", "force"}:
        raise ValueError(f"invalid preflight_mode: {preflight_mode!r} (expected enforce|off|force)")

    if sbpl_file is None:
        default_sbpl_text = """(version 1)
(deny default)
(allow process*)
(allow file-read* (subpath "/System"))
"""
        sbpl_abs = ensure_absolute(DEFAULT_APPLY_ATTEMPT_SBPL, repo_root)
        sbpl_abs.parent.mkdir(parents=True, exist_ok=True)
        sbpl_abs.write_text(default_sbpl_text)
    else:
        sbpl_abs = ensure_absolute(sbpl_file, repo_root)

    wrapper = ensure_absolute(Path("book/tools/sbpl/wrapper/wrapper"), repo_root)
    if not wrapper.exists():
        raise FileNotFoundError(f"sbpl wrapper missing: {to_repo_relative(wrapper, repo_root)}")

    target = Path("/usr/bin/true")
    cmd = [
        to_repo_relative(wrapper, repo_root),
        "--preflight",
        preflight_mode,
        "--sbpl",
        to_repo_relative(sbpl_abs, repo_root),
        "--",
        str(target),
    ]
    res = _run(cmd, repo_root=repo_root, timeout_s=10)

    sbpl_apply_markers = rt_contract.extract_sbpl_apply_markers(res.stderr)
    sbpl_preflight_markers = rt_contract.extract_sbpl_preflight_markers(res.stderr)
    apply_report = rt_contract.derive_apply_report_from_markers(sbpl_apply_markers)

    payload: Dict[str, Any] = {
        "kind": "apply-attempt",
        "world_id": _load_world_id(repo_root),
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "sbpl_file": to_repo_relative(sbpl_abs, repo_root),
        "wrapper": to_repo_relative(wrapper, repo_root),
        "preflight_mode": preflight_mode,
        "target": str(target),
        "returncode": res.returncode,
        "command": relativize_command(cmd, repo_root),
        "apply_report": apply_report,
        "sbpl_apply_markers": sbpl_apply_markers,
        "sbpl_preflight_markers": sbpl_preflight_markers,
        "stderr": rt_contract.strip_tool_markers(res.stderr),
        "limits": [
            "Apply-stage `EPERM` is almost always evidence of a staging problem, not a policy denial. Run `book/tools/preflight`.",
            "Wrapper preflight may block known gated signatures before apply; interpret apply-attempt alongside preflight_scan results.",
        ],
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return {"status": "ok", "out_path": to_repo_relative(out_path, repo_root)}


def write_validation_out(*, repo_root: Path | None = None) -> None:
    repo_root = repo_root or find_repo_root()
    ent_path = ensure_absolute(DEFAULT_ENTITLEMENTS_OUT, repo_root)
    ext_path = ensure_absolute(DEFAULT_EXTENSIONS_OUT, repo_root)
    platform_path = ensure_absolute(DEFAULT_PLATFORM_OUT, repo_root)
    containers_path = ensure_absolute(DEFAULT_CONTAINERS_OUT, repo_root)
    apply_path = ensure_absolute(DEFAULT_APPLY_ATTEMPT_OUT, repo_root)
    capture_entitlements_evolution(ent_path, repo_root=repo_root, build=True)
    capture_extensions_dynamic(ext_path, repo_root=repo_root, build=True)
    capture_platform_policy(platform_path, repo_root=repo_root, build=True)
    capture_containers(containers_path, repo_root=repo_root, build=True)
    capture_apply_attempt(apply_path, repo_root=repo_root)
    print(f"[+] wrote {to_repo_relative(ent_path, repo_root)}")
    print(f"[+] wrote {to_repo_relative(ext_path, repo_root)}")
    print(f"[+] wrote {to_repo_relative(platform_path, repo_root)}")
    print(f"[+] wrote {to_repo_relative(containers_path, repo_root)}")
    print(f"[+] wrote {to_repo_relative(apply_path, repo_root)}")
