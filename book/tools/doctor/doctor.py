#!/usr/bin/env python3
"""
World baseline checkup tool (hypothesis-tier signals only).

Doctor compares a baseline hypothesis (world.json + dyld/manifest.json)
to host signals and emits a report + witness snippet. It does not update any
mapping or CARTON artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils  # type: ignore
from book.api.profile import compile as compile_mod  # type: ignore
from book.api.profile import decoder as decoder_mod  # type: ignore


SCHEMA_VERSION = 1
DEFAULT_OUT_ROOT = Path(__file__).resolve().parent / "out"
DEFAULT_SMOKE_SBPL = "(version 1)\n(deny default)\n(allow file-read*)\n"
DYLD_UUID_OFFSET = 0x58
DYLD_UUID_LEN = 16
WORLD_REGISTRY = REPO_ROOT / "book" / "world" / "registry.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _rel(path: Optional[Path]) -> Optional[str]:
    if path is None:
        return None
    return path_utils.to_repo_relative(path, repo_root=REPO_ROOT)


def _sha256_bytes(blob: bytes) -> str:
    h = hashlib.sha256()
    h.update(blob)
    return h.hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _load_json(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        return json.loads(path.read_text()), None
    except FileNotFoundError:
        return None, "missing"
    except json.JSONDecodeError as exc:
        return None, f"json_error: {exc}"
    except Exception as exc:
        return None, f"error: {exc}"


def _load_registry() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not WORLD_REGISTRY.exists():
        return None, "missing"
    return _load_json(WORLD_REGISTRY)


def _run_command(cmd: List[str], timeout: int = 5) -> Dict[str, Any]:
    record: Dict[str, Any] = {"command": path_utils.relativize_command(cmd, repo_root=REPO_ROOT)}
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        record.update(
            {
                "status": "ok" if res.returncode == 0 else "error",
                "returncode": res.returncode,
                "stdout": (res.stdout or "").strip(),
                "stderr": (res.stderr or "").strip(),
            }
        )
    except FileNotFoundError as exc:
        record.update({"status": "error", "error": "command_not_found", "exception": str(exc)})
    except subprocess.TimeoutExpired:
        record.update({"status": "error", "error": "timeout"})
    except Exception as exc:
        record.update({"status": "error", "error": "exception", "exception": str(exc)})
    return record


def _cmd_value(rec: Dict[str, Any]) -> Optional[str]:
    val = rec.get("stdout")
    if isinstance(val, str) and val.strip():
        return val.strip()
    return None


def _normalize_sip(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    lowered = value.lower()
    if "disabled" in lowered:
        return "disabled"
    if "enabled" in lowered:
        return "enabled"
    return value.strip()


def _compare_simple(expected: Optional[str], observed: Optional[str], normalize=None) -> Dict[str, Any]:
    if expected is None:
        return {"status": "skipped", "expected": None, "observed": observed}
    if observed is None:
        return {"status": "unknown", "expected": expected, "observed": None}
    if normalize is None:
        status = "match" if expected == observed else "mismatch"
        return {"status": status, "expected": expected, "observed": observed}
    exp_norm = normalize(expected)
    obs_norm = normalize(observed)
    status = "match" if exp_norm == obs_norm else "mismatch"
    return {
        "status": status,
        "expected": expected,
        "observed": observed,
        "expected_norm": exp_norm,
        "observed_norm": obs_norm,
    }


def _compare_kernel(expected: Optional[str], observed_r: Optional[str], observed_v: Optional[str]) -> Dict[str, Any]:
    if expected is None:
        return {"status": "skipped", "expected": None, "observed": {"uname_r": observed_r, "uname_v": observed_v}}
    if observed_r is None and observed_v is None:
        return {"status": "unknown", "expected": expected, "observed": {"uname_r": None, "uname_v": None}}
    match = expected == observed_r or expected == observed_v
    return {
        "status": "match" if match else "mismatch",
        "expected": expected,
        "observed": {"uname_r": observed_r, "uname_v": observed_v},
    }


def _resolve_world_input(world_arg: str) -> Dict[str, Any]:
    resolved: Dict[str, Any] = {
        "input_value": world_arg,
        "input_path": None,
        "input_kind": None,
        "world_dir": None,
        "baseline_path": None,
        "manifest_path": None,
        "registry": None,
        "errors": [],
    }
    world_abs = path_utils.ensure_absolute(Path(world_arg), REPO_ROOT)
    if world_abs.exists():
        resolved["input_path"] = _rel(world_abs)
        if world_abs.is_dir():
            resolved["input_kind"] = "world_dir"
            resolved["world_dir"] = _rel(world_abs)
            baseline = world_abs / "world.json"
            if baseline.exists():
                resolved["baseline_path"] = _rel(baseline)
            manifest = world_abs / "dyld" / "manifest.json"
            if manifest.exists():
                resolved["manifest_path"] = _rel(manifest)
        elif world_abs.is_file():
            name = world_abs.name
            if name == "world.json":
                resolved["input_kind"] = "world_json"
                resolved["world_dir"] = _rel(world_abs.parent)
                resolved["baseline_path"] = _rel(world_abs)
                manifest = world_abs.parent / "dyld" / "manifest.json"
                if manifest.exists():
                    resolved["manifest_path"] = _rel(manifest)
            elif name == "manifest.json" and world_abs.parent.name == "dyld":
                resolved["input_kind"] = "dyld_manifest"
                world_dir = world_abs.parent.parent
                resolved["world_dir"] = _rel(world_dir)
                resolved["manifest_path"] = _rel(world_abs)
                baseline = world_dir / "world.json"
                if baseline.exists():
                    resolved["baseline_path"] = _rel(baseline)
            else:
                resolved["errors"].append(f"unsupported input file: {name}")
        else:
            resolved["errors"].append("input path not found")
        return resolved

    registry, reg_err = _load_registry()
    if reg_err:
        resolved["errors"].append(f"registry_{reg_err}")
        return resolved
    worlds = (registry or {}).get("worlds") or []
    match = None
    for entry in worlds:
        if not isinstance(entry, dict):
            continue
        if entry.get("world_name") == world_arg or entry.get("world_id") == world_arg:
            match = entry
            break
    if not match:
        resolved["errors"].append("world_not_found_in_registry")
        return resolved
    resolved["input_kind"] = "registry_world_name" if match.get("world_name") == world_arg else "registry_world_id"
    resolved["registry"] = {
        "path": _rel(WORLD_REGISTRY),
        "world_name": match.get("world_name"),
        "world_id": match.get("world_id"),
        "world_path": match.get("world_path"),
    }
    world_path_val = match.get("world_path")
    if isinstance(world_path_val, str):
        world_path = path_utils.ensure_absolute(Path(world_path_val), REPO_ROOT)
        resolved["baseline_path"] = _rel(world_path)
        resolved["world_dir"] = _rel(world_path.parent)
        resolved["input_path"] = _rel(world_path)
    else:
        resolved["errors"].append("registry_entry_missing_world_path")
    return resolved


def _manifest_hash_check(manifest_path: Path) -> Dict[str, Any]:
    out: Dict[str, Any] = {"status": "error"}
    try:
        raw = manifest_path.read_bytes()
        digest = _sha256_bytes(raw)
        out.update({"status": "ok", "sha256": digest, "sha8": digest[:8]})
    except Exception as exc:
        out["error"] = str(exc)
    return out


def _check_manifest_libs(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    libs = manifest.get("libs") or []
    out: List[Dict[str, Any]] = []
    if not isinstance(libs, list):
        return [{"status": "error", "error": "libs is not a list"}]
    for idx, entry in enumerate(libs):
        rec: Dict[str, Any] = {"index": idx, "status": "ok"}
        if not isinstance(entry, dict):
            rec.update({"status": "error", "error": "entry not a dict"})
            out.append(rec)
            continue
        path_val = entry.get("path")
        rec["path"] = path_val
        if not isinstance(path_val, str):
            rec.update({"status": "error", "error": "missing path"})
            out.append(rec)
            continue
        abs_path = path_utils.ensure_absolute(Path(path_val), REPO_ROOT)
        rec["path"] = _rel(abs_path)
        if not abs_path.exists():
            rec.update({"status": "error", "error": "missing file"})
            out.append(rec)
            continue
        size_expected = entry.get("size")
        sha_expected = entry.get("sha256")
        size_actual = abs_path.stat().st_size
        rec["size_expected"] = size_expected
        rec["size_actual"] = size_actual
        if isinstance(size_expected, int):
            rec["size_match"] = size_expected == size_actual
        else:
            rec["size_match"] = None
        try:
            sha_actual = _sha256_file(abs_path)
            rec["sha256_expected"] = sha_expected
            rec["sha256_actual"] = sha_actual
            if isinstance(sha_expected, str):
                rec["sha256_match"] = sha_expected == sha_actual
            else:
                rec["sha256_match"] = None
        except Exception as exc:
            rec["sha256_error"] = str(exc)
            rec["sha256_match"] = False
        if rec.get("size_match") is False or rec.get("sha256_match") is False:
            rec["status"] = "error"
        out.append(rec)
    return out


def _dyld_cache_candidates(arch: Optional[str]) -> List[Dict[str, Any]]:
    names: List[str] = []
    if arch:
        names.append(f"dyld_shared_cache_{arch}")
    if arch == "arm64":
        names.append("dyld_shared_cache_arm64e")
    for name in ["dyld_shared_cache_arm64e", "dyld_shared_cache_arm64", "dyld_shared_cache_x86_64"]:
        if name not in names:
            names.append(name)
    bases = [
        Path("/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld"),
        Path("/System/Volumes/Preboot/Cryptexes/Incoming/OS/System/Library/dyld"),
        Path("/System/Library/dyld"),
    ]
    out: List[Dict[str, Any]] = []
    for base in bases:
        for name in names:
            path = base / name
            out.append(
                {
                    "path": str(path),
                    "base": str(base),
                    "name": name,
                    "exists": path.exists(),
                }
            )
    return out


def _read_dyld_cache_uuid(path: Path) -> Dict[str, Any]:
    rec: Dict[str, Any] = {
        "path": str(path),
        "uuid_offset": DYLD_UUID_OFFSET,
        "uuid_len": DYLD_UUID_LEN,
        "status": "error",
    }
    try:
        with path.open("rb") as fh:
            header = fh.read(max(DYLD_UUID_OFFSET + DYLD_UUID_LEN, 0x100))
        if len(header) < DYLD_UUID_OFFSET + DYLD_UUID_LEN:
            rec["error"] = "header_too_small"
            return rec
        magic = header[:16].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        uuid_bytes = header[DYLD_UUID_OFFSET : DYLD_UUID_OFFSET + DYLD_UUID_LEN]
        rec["magic"] = magic
        rec["uuid_bytes_hex"] = uuid_bytes.hex()
        rec["uuid_sha8"] = _sha256_bytes(uuid_bytes)[:8]
        try:
            rec["uuid"] = str(uuid.UUID(bytes=uuid_bytes))
        except ValueError:
            rec["uuid"] = uuid_bytes.hex()
        rec["status"] = "ok"
    except Exception as exc:
        rec["error"] = str(exc)
    return rec


def _compile_smoke(world_dir: Optional[Path], out_dir: Path) -> Dict[str, Any]:
    rec: Dict[str, Any] = {"status": "error"}
    smoke_path = None
    if world_dir:
        candidate = world_dir / "doctor" / "compile_smoke.sb"
        if candidate.exists():
            smoke_path = candidate
    try:
        if smoke_path:
            rec["source"] = {"kind": "file", "path": _rel(smoke_path)}
            compiled = compile_mod.compile_sbpl_file(smoke_path)
        else:
            rec["source"] = {"kind": "inline", "text": DEFAULT_SMOKE_SBPL}
            compiled = compile_mod.compile_sbpl_string(DEFAULT_SMOKE_SBPL)
        blob = compiled.blob
        rec["status"] = "ok"
        rec["profile_type"] = compiled.profile_type
        rec["blob_len"] = len(blob)
        rec["blob_sha256"] = _sha256_bytes(blob)
        blob_path = out_dir / "compile_smoke.sb.bin"
        blob_path.write_bytes(blob)
        rec["blob_path"] = _rel(blob_path)
        prof = decoder_mod.decode_profile(blob)
        rec["decode_summary"] = {
            "format_variant": prof.format_variant,
            "op_count": prof.op_count,
            "maybe_flags": prof.header_fields.get("maybe_flags"),
            "word0": prof.preamble_words_full[0] if prof.preamble_words_full else None,
            "word2": prof.preamble_words_full[2] if len(prof.preamble_words_full) > 2 else None,
            "profile_class": prof.header_fields.get("profile_class"),
            "profile_class_word_index": prof.header_fields.get("profile_class_word_index"),
        }
    except Exception as exc:
        rec["status"] = "error"
        rec["error"] = str(exc)
    return rec


def _compute_world_match(comparisons: Dict[str, Any]) -> str:
    status_values = [comp.get("status") for comp in comparisons.values()]
    if any(s == "mismatch" for s in status_values):
        return "mismatch"
    if any(s == "unknown" for s in status_values):
        return "inconclusive"
    return "likely_match"


def _render_witness(report: Dict[str, Any]) -> str:
    baseline = report.get("baseline") or {}
    integrity = report.get("baseline_integrity") or {}
    comparisons = report.get("comparisons") or {}
    dyld_cache = report.get("dyld_cache") or {}
    compile_smoke = report.get("compile_smoke") or {}
    world_id = baseline.get("world_id") or "unknown"
    lines = [
        "doctor_witness:",
        f"  world_id: {world_id}",
        f"  baseline: {baseline.get('path') or 'missing'}",
        f"  dyld_manifest: {baseline.get('dyld_manifest') or 'missing'}",
        f"  manifest_sha8: {integrity.get('manifest_sha8') or 'unknown'}",
        f"  world_id_suffix_match: {integrity.get('world_id_suffix_match')}",
    ]
    for key in ["version", "build", "kernel", "machine", "sip"]:
        comp = comparisons.get(key) or {}
        lines.append(
            f"  {key}: expected={comp.get('expected')} observed={comp.get('observed')} status={comp.get('status')}"
        )
    lines.append(f"  dyld_cache_path: {dyld_cache.get('selected_path') or 'not_found'}")
    lines.append(f"  dyld_cache_uuid: {dyld_cache.get('uuid') or 'unknown'}")
    lines.append(f"  dyld_cache_uuid_sha8: {dyld_cache.get('uuid_sha8') or 'unknown'}")
    lines.append(f"  compile_smoke_status: {compile_smoke.get('status')}")
    if compile_smoke.get("blob_sha256"):
        lines.append(f"  compile_smoke_blob_sha256: {compile_smoke.get('blob_sha256')}")
    if compile_smoke.get("decode_summary"):
        lines.append(f"  compile_smoke_op_count: {compile_smoke['decode_summary'].get('op_count')}")
    lines.append(f"  verdict: {report.get('verdict', {}).get('world_match')}")
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Check a world baseline hypothesis against host signals.")
    parser.add_argument(
        "--world",
        required=True,
        help="World directory, world.json, dyld/manifest.json, or registry world name/id",
    )
    parser.add_argument("--out", help="Output directory (default: book/tools/doctor/out/<world_id or unknown>)")
    parser.add_argument("--no-compile-smoke", action="store_true", help="Skip compile/decode smoke test")
    args = parser.parse_args(argv)

    resolution = _resolve_world_input(args.world)
    errors: List[Dict[str, Any]] = []
    if resolution.get("errors"):
        for err in resolution["errors"]:
            errors.append({"stage": "resolve", "error": err})

    baseline_path = (
        path_utils.ensure_absolute(Path(resolution["baseline_path"]), REPO_ROOT)
        if resolution.get("baseline_path")
        else None
    )
    manifest_path_input = (
        path_utils.ensure_absolute(Path(resolution["manifest_path"]), REPO_ROOT)
        if resolution.get("manifest_path")
        else None
    )
    if baseline_path is None:
        errors.append({"stage": "baseline", "error": "baseline_missing"})

    baseline_doc: Optional[Dict[str, Any]] = None
    if baseline_path:
        baseline_doc, err = _load_json(baseline_path)
        if err:
            errors.append({"stage": "baseline", "path": _rel(baseline_path), "error": err})

    manifest_path = manifest_path_input
    manifest_path_declared = None
    if baseline_doc:
        manifest_ref = baseline_doc.get("dyld_manifest")
        if isinstance(manifest_ref, str):
            manifest_path_declared = path_utils.ensure_absolute(Path(manifest_ref), REPO_ROOT)
            if manifest_path is None:
                manifest_path = manifest_path_declared
            elif manifest_path != manifest_path_declared:
                errors.append(
                    {
                        "stage": "baseline",
                        "error": "manifest path mismatch",
                        "manifest_input": _rel(manifest_path),
                        "manifest_declared": _rel(manifest_path_declared),
                    }
                )
    if manifest_path and not resolution.get("manifest_path"):
        resolution["manifest_path"] = _rel(manifest_path)

    manifest_doc: Optional[Dict[str, Any]] = None
    if manifest_path:
        manifest_doc, err = _load_json(manifest_path)
        if err:
            errors.append({"stage": "manifest", "path": _rel(manifest_path), "error": err})

    baseline_world_id = baseline_doc.get("world_id") if baseline_doc else None

    out_dir = None
    if args.out:
        out_dir = path_utils.ensure_absolute(Path(args.out), REPO_ROOT)
    else:
        suffix = baseline_world_id or "unknown-world"
        out_dir = DEFAULT_OUT_ROOT / suffix
    out_dir.mkdir(parents=True, exist_ok=True)

    baseline_integrity: Dict[str, Any] = {
        "status": "ok",
        "issues": [],
        "manifest_sha8": None,
        "manifest_sha256": None,
        "world_id_suffix_match": None,
        "manifest_world_id_match": None,
        "manifest_hash_doc": None,
        "manifest_hash_match": None,
    }

    if manifest_path:
        manifest_hash = _manifest_hash_check(manifest_path)
        baseline_integrity["manifest_sha256"] = manifest_hash.get("sha256")
        baseline_integrity["manifest_sha8"] = manifest_hash.get("sha8")
        if manifest_hash.get("status") != "ok":
            baseline_integrity["manifest_hash_error"] = manifest_hash.get("error")
        if manifest_hash.get("status") != "ok":
            baseline_integrity["status"] = "error"
            baseline_integrity["issues"].append({"level": "error", "error": "manifest_hash_failed"})
        if baseline_world_id and manifest_hash.get("sha8"):
            expected_suffix = f"-dyld-{manifest_hash['sha8']}"
            match = str(baseline_world_id).endswith(expected_suffix)
            baseline_integrity["world_id_suffix_match"] = match
            if not match:
                baseline_integrity["status"] = "error"
                baseline_integrity["issues"].append(
                    {
                        "level": "error",
                        "error": "world_id_suffix_mismatch",
                        "expected_suffix": expected_suffix,
                    }
                )
        if manifest_doc and isinstance(manifest_doc.get("world_id"), str) and baseline_world_id:
            manifest_world_id = manifest_doc.get("world_id")
            match = manifest_world_id == baseline_world_id
            baseline_integrity["manifest_world_id_match"] = match
            if not match:
                baseline_integrity["status"] = "error"
                baseline_integrity["issues"].append(
                    {
                        "level": "error",
                        "error": "manifest_world_id_mismatch",
                        "manifest_world_id": manifest_world_id,
                    }
                )
    else:
        baseline_integrity["status"] = "warning"
        baseline_integrity["issues"].append({"level": "warning", "error": "manifest_missing"})

    manifest_hash_ref = baseline_doc.get("dyld_manifest_hash") if baseline_doc else None
    if isinstance(manifest_hash_ref, str):
        manifest_hash_path = path_utils.ensure_absolute(Path(manifest_hash_ref), REPO_ROOT)
        hash_doc, err = _load_json(manifest_hash_path)
        if err:
            baseline_integrity["manifest_hash_doc"] = {
                "path": _rel(manifest_hash_path),
                "status": "error",
                "error": err,
            }
            baseline_integrity["issues"].append({"level": "warning", "error": "manifest_hash_unreadable"})
        else:
            baseline_integrity["manifest_hash_doc"] = {
                "path": _rel(manifest_hash_path),
                "status": "ok",
                "sha256": hash_doc.get("sha256") if hash_doc else None,
                "sha8": hash_doc.get("sha8") if hash_doc else None,
            }
            if baseline_integrity.get("manifest_sha256") and hash_doc:
                expected = hash_doc.get("sha256")
                match = expected == baseline_integrity.get("manifest_sha256")
                baseline_integrity["manifest_hash_match"] = match
                if expected is not None and not match:
                    baseline_integrity["status"] = "error"
                    baseline_integrity["issues"].append({"level": "error", "error": "manifest_hash_mismatch"})

    if manifest_doc:
        libs_checks = _check_manifest_libs(manifest_doc)
        baseline_integrity["libs"] = libs_checks
        if any(entry.get("status") == "error" for entry in libs_checks):
            baseline_integrity["status"] = "error"
            baseline_integrity["issues"].append({"level": "error", "error": "manifest_lib_mismatch"})
    else:
        baseline_integrity["libs"] = []

    sw_product = _run_command(["sw_vers", "-productName"])
    sw_version = _run_command(["sw_vers", "-productVersion"])
    sw_build = _run_command(["sw_vers", "-buildVersion"])
    sw_extra = _run_command(["sw_vers", "-productVersionExtra"])
    uname_r = _run_command(["uname", "-r"])
    uname_v = _run_command(["uname", "-v"])
    uname_m = _run_command(["uname", "-m"])
    csrutil = _run_command(["csrutil", "status"])

    host = {
        "sw_vers": {
            "product": sw_product,
            "version": sw_version,
            "build": sw_build,
            "extra": sw_extra,
        },
        "uname": {
            "r": uname_r,
            "v": uname_v,
            "m": uname_m,
        },
        "csrutil": csrutil,
    }

    expected_host = baseline_doc.get("host") if baseline_doc else {}
    comparisons = {
        "product": _compare_simple(expected_host.get("product") if expected_host else None, _cmd_value(sw_product)),
        "version": _compare_simple(expected_host.get("version") if expected_host else None, _cmd_value(sw_version)),
        "build": _compare_simple(expected_host.get("build") if expected_host else None, _cmd_value(sw_build)),
        "kernel": _compare_kernel(
            expected_host.get("kernel") if expected_host else None,
            _cmd_value(uname_r),
            _cmd_value(uname_v),
        ),
        "machine": _compare_simple(expected_host.get("machine") if expected_host else None, _cmd_value(uname_m)),
        "sip": _compare_simple(
            expected_host.get("sip") if expected_host else None,
            _cmd_value(csrutil),
            normalize=_normalize_sip,
        ),
    }

    dyld_candidates = _dyld_cache_candidates(_cmd_value(uname_m))
    selected = next((c for c in dyld_candidates if c.get("exists")), None)
    dyld_cache: Dict[str, Any] = {
        "candidates": dyld_candidates,
        "selected_path": selected["path"] if selected else None,
        "uuid": None,
        "uuid_sha8": None,
        "uuid_source": "header_offset_0x58 (hypothesis)",
        "incoming_dir_present": Path("/System/Volumes/Preboot/Cryptexes/Incoming/OS/System/Library/dyld").exists(),
    }
    if selected:
        cache_path = Path(selected["path"])
        uuid_rec = _read_dyld_cache_uuid(cache_path)
        dyld_cache["uuid"] = uuid_rec.get("uuid")
        dyld_cache["uuid_sha8"] = uuid_rec.get("uuid_sha8")
        dyld_cache["uuid_record"] = uuid_rec
        dyld_cache["siblings"] = sorted(p.name for p in cache_path.parent.glob(cache_path.name + ".*"))

    tmp_path = Path("/tmp")
    confounders = {
        "tmp_symlink": {
            "path": str(tmp_path),
            "is_symlink": tmp_path.is_symlink(),
            "realpath": str(tmp_path.resolve()) if tmp_path.exists() else None,
        },
        "tcc_state": baseline_doc.get("tcc_state") if baseline_doc else None,
        "profile_format_variant": baseline_doc.get("profile_format_variant") if baseline_doc else None,
        "apply_gates": baseline_doc.get("apply_gates") if baseline_doc else None,
        "product_version_extra": _cmd_value(sw_extra),
    }

    compile_smoke = {"status": "skipped"}
    if not args.no_compile_smoke:
        world_dir = None
        if resolution.get("world_dir"):
            world_dir = path_utils.ensure_absolute(Path(resolution["world_dir"]), REPO_ROOT)
        compile_smoke = _compile_smoke(world_dir, out_dir)

    world_match = _compute_world_match(comparisons)
    if baseline_doc is None:
        world_match = "inconclusive"
    verdict = {
        "world_match": world_match,
        "baseline_integrity": baseline_integrity.get("status"),
    }

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _now_iso(),
        "inputs": resolution,
        "baseline": {
            "path": _rel(baseline_path),
            "world_id": baseline_world_id,
            "host": expected_host,
            "dyld_manifest": _rel(manifest_path) if manifest_path else None,
            "dyld_manifest_hash": baseline_doc.get("dyld_manifest_hash") if baseline_doc else None,
            "profile_format_variant": baseline_doc.get("profile_format_variant") if baseline_doc else None,
            "apply_gates": baseline_doc.get("apply_gates") if baseline_doc else None,
            "tcc_state": baseline_doc.get("tcc_state") if baseline_doc else None,
        },
        "baseline_integrity": baseline_integrity,
        "host": host,
        "comparisons": comparisons,
        "dyld_cache": dyld_cache,
        "confounders": confounders,
        "compile_smoke": compile_smoke,
        "verdict": verdict,
        "errors": errors,
        "out_dir": _rel(out_dir),
    }

    report_path = out_dir / "doctor_report.json"
    witness_path = out_dir / "doctor_witness.txt"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True))
    witness_path.write_text(_render_witness(report))
    print(f"[+] wrote {report_path}")
    print(f"[+] wrote {witness_path}")

    if verdict["world_match"] == "likely_match" and baseline_integrity.get("status") == "ok":
        return 0
    if verdict["world_match"] == "mismatch" or baseline_integrity.get("status") == "error":
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
