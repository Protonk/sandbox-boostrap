#!/usr/bin/env python3
"""
Metadata sandbox runner:
- Compile SBPL probes for metadata-only operations across alias/canonical paths.
- Build a Swift runner that applies a compiled blob and performs metadata syscalls.
- Run matrix of profile × op × path to capture allow/deny with errno details.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import find_repo_root  # type: ignore
from book.api.profile_tools import decoder  # type: ignore
from book.api.profile_tools import compile_sbpl_string  # type: ignore

BASE_DIR = Path(__file__).resolve().parent
SB_DIR = BASE_DIR / "sb"
BUILD_DIR = SB_DIR / "build"
RUNNER_SRC = BASE_DIR / "metadata_runner.swift"
RUNNER_BUILD_DIR = BASE_DIR / "build"
RUNNER_BIN = RUNNER_BUILD_DIR / "metadata_runner"
OUT_DIR = BASE_DIR / "out"
WORLD_PATH = find_repo_root(Path(__file__)) / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world-baseline.json"

PROFILE_SOURCES = {
    "literal_alias_only": SB_DIR / "metadata_alias_only.sb",
    "literal_canonical_only": SB_DIR / "metadata_canonical_only.sb",
    "literal_both_paths": SB_DIR / "metadata_both_paths.sb",
    "subpath_alias_only": SB_DIR / "metadata_subpath_alias_only.sb",
    "subpath_canonical_only": SB_DIR / "metadata_subpath_canonical_only.sb",
    "subpath_both_paths": SB_DIR / "metadata_subpath_both_paths.sb",
    "regex_alias_only": SB_DIR / "metadata_regex_alias_only.sb",
    "regex_canonical_only": SB_DIR / "metadata_regex_canonical_only.sb",
    "regex_both_paths": SB_DIR / "metadata_regex_both_paths.sb",
}

PATH_PAIRS = [
    ("/tmp/foo", "/private/tmp/foo"),
    ("/tmp/bar", "/private/tmp/bar"),
    ("/tmp/nested/child", "/private/tmp/nested/child"),
    ("/var/tmp/canon", "/private/var/tmp/canon"),
]
OPS = ["file-read-metadata", "file-write*"]
READ_SYSCALLS = ["lstat", "getattrlist", "setattrlist", "fstat"]
READ_ATTR_PAYLOADS = ["cmn", "cmn-name", "cmn-times", "file-size"]
WRITE_SYSCALLS = ["chmod", "utimes", "fchmod", "futimes", "lchown", "fchown", "fchownat", "lutimes"]


def _literal_candidates(s: str) -> set[str]:
    """
    Generate plausible path forms for a decoder literal string.

    Literal strings in the decoder carry a leading type byte (and sometimes a
    leading newline). Drop that byte, trim whitespace, and add a leading slash
    when it is missing so we can compare against anchors exactly.
    """
    out: set[str] = set()
    if not s:
        return out
    trimmed = s.lstrip()
    if trimmed.startswith("/"):
        out.add(trimmed)
    if trimmed:
        body = trimmed[1:]  # drop the type byte
        out.add(body)
        if body and not body.startswith("/"):
            out.add(f"/{body}")
    return out


def anchor_present(anchor: str, literals: set[str]) -> bool:
    """Heuristic presence check for anchors from normalized literal strings."""
    if anchor in literals:
        return True
    parts = anchor.strip("/").split("/")
    if not parts:
        return False
    first = f"/{parts[0]}/"
    if first not in literals:
        return False
    if len(parts) == 1:
        return True
    tail = "/".join(parts[1:])
    if tail in literals or f"/{tail}" in literals:
        return True
    if len(parts) >= 3:
        mid = f"{parts[1]}/"
        tail_rest = "/".join(parts[2:])
        if ((mid in literals) or (f"/{parts[1]}/" in literals)) and (
            (tail_rest in literals) or (f"/{tail_rest}" in literals)
        ):
            return True
    if all(((seg in literals) or (f"/{seg}" in literals) or (f"{seg}/" in literals)) for seg in parts[1:]):
        return True
    return False


def load_world_id() -> str:
    data = json.loads(WORLD_PATH.read_text())
    return data.get("world_id") or data.get("id", "unknown-world")


def compile_profiles() -> Dict[str, Path]:
    """Compile SBPL probes to blobs under sb/build."""
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    blobs: Dict[str, Path] = {}
    for profile_id, sb_path in PROFILE_SOURCES.items():
        blob = compile_sbpl_string(sb_path.read_text()).blob
        blob_path = BUILD_DIR / f"{sb_path.stem}.sb.bin"
        blob_path.write_bytes(blob)
        blobs[profile_id] = blob_path
    return blobs


def decode_profiles(blobs: Dict[str, Path]) -> Path:
    """Decode compiled blobs and summarize anchors."""
    anchors = sorted({p for pair in PATH_PAIRS for p in pair})
    decode: Dict[str, Any] = {}
    for profile_id, blob_path in blobs.items():
        dec = decoder.decode_profile_dict(blob_path.read_bytes())
        literal_set = set()
        for lit in dec.get("literal_strings") or []:
            literal_set.update(_literal_candidates(lit))
        anchor_info = [
            {"path": anchor, "present": anchor_present(anchor, literal_set)} for anchor in anchors
        ]
        decode[profile_id] = {
            "anchors": anchor_info,
            "node_count": dec.get("node_count"),
            "tag_counts": dec.get("tag_counts"),
        }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "decode_profiles.json"
    out_path.write_text(json.dumps(decode, indent=2))
    return out_path


def build_runner() -> Path:
    """Compile the Swift metadata runner."""
    RUNNER_BUILD_DIR.mkdir(parents=True, exist_ok=True)
    cmd = ["swiftc", str(RUNNER_SRC), "-o", str(RUNNER_BIN)]
    subprocess.run(cmd, check=True, cwd=BASE_DIR)
    return RUNNER_BIN


def ensure_fixtures() -> None:
    """Ensure canonical fixture files exist for all target paths."""
    for _, canonical in PATH_PAIRS:
        p = Path(canonical)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"metadata-runner fixture for {p.name}\n")
        p.chmod(0o640)


def run_probe(binary: Path, sb_path: Path, op: str, syscall: str, attr_payload: str, path: str) -> Dict[str, Any]:
    """Run a single probe through the Swift runner and parse JSON output."""
    cmd = [
        str(binary),
        "--sbpl",
        str(sb_path),
        "--op",
        op,
        "--syscall",
        syscall,
        "--attr-payload",
        attr_payload,
        "--path",
        path,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=BASE_DIR)
    stdout = proc.stdout.strip()
    record: Dict[str, Any] = {
        "stdout": stdout,
        "stderr": proc.stderr.strip(),
        "returncode": proc.returncode,
    }
    if stdout:
        try:
            record.update(json.loads(stdout))
        except json.JSONDecodeError:
            record["parse_error"] = "failed to decode runner stdout as JSON"
    else:
        record["parse_error"] = "empty stdout"
    return record


def run_matrix(binary: Path, blobs: Dict[str, Path]) -> Path:
    results: List[Dict[str, Any]] = []
    for profile_id, blob in blobs.items():
        sb_path = PROFILE_SOURCES[profile_id]
        for op in OPS:
            syscalls = READ_SYSCALLS if op == "file-read-metadata" else WRITE_SYSCALLS
            for alias, canonical in PATH_PAIRS:
                for target in (alias, canonical):
                    for syscall in syscalls:
                        payloads = READ_ATTR_PAYLOADS if (op == "file-read-metadata" and syscall in ("getattrlist", "setattrlist")) else ["cmn"]
                        for payload in payloads:
                            rec = run_probe(binary, sb_path, op, syscall, payload, target)
                            rec.update(
                                {
                                    "profile_id": profile_id,
                                    "operation": op,
                                    "syscall": syscall,
                                    "attr_payload": payload,
                                    "requested_path": target,
                                    "sbpl": str(sb_path),
                                    "blob": str(blob),
                                }
                            )
                            results.append(rec)
    payload = {"world_id": load_world_id(), "results": results}
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "runtime_results.json"
    out_path.write_text(json.dumps(payload, indent=2))
    return out_path


def main() -> int:
    world_id = load_world_id()
    print(f"[+] world: {world_id}")
    blobs = compile_profiles()
    print(f"[+] compiled {len(blobs)} profiles")
    decode_profiles(blobs)
    runner = build_runner()
    print(f"[+] built runner at {runner}")
    ensure_fixtures()
    runtime_path = run_matrix(runner, blobs)
    print(f"[+] runtime results -> {runtime_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
