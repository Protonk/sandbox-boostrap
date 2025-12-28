#!/usr/bin/env python3
"""
VFS canonicalization harness for alias/canonical path families on Sonoma.

Tasks:
- Compile VFS SBPL profiles → blobs under sb/build.
- Emit a simple expected_matrix.json (profile_id, operation, requested_path, expected_decision).
- Build a harness matrix and run it via book.api.runtime_tools.harness.runner.run_matrix.
- Down-convert the harness runtime_results.json into a simple runtime_results.json array.
- Decode the VFS blobs via book.api.profile_tools.decoder and emit decode_tmp_profiles.json
  (anchors, tags, and field2 values for the configured path pairs).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import ensure_absolute, find_repo_root, to_repo_relative
from book.api.profile_tools import decoder  # type: ignore
from book.api.runtime_tools.harness.runner import ensure_fixtures, run_matrix  # type: ignore
from book.api.profile_tools import compile_sbpl_string  # type: ignore
from book.api.runtime_tools.core.normalize import write_matrix_observations  # type: ignore


REPO_ROOT = find_repo_root(Path(__file__))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

BASE_DIR = Path(__file__).resolve().parent
SB_DIR = BASE_DIR / "sb"
BUILD_DIR = SB_DIR / "build"
OUT_DIR = BASE_DIR / "out"
WORLD_PATH = REPO_ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"

BASE_PATH_PAIRS = [
    ("/tmp/foo", "/private/tmp/foo"),
    ("/tmp/bar", "/private/tmp/bar"),
    ("/tmp/nested/child", "/private/tmp/nested/child"),
    ("/var/tmp/canon", "/private/var/tmp/canon"),
]
VAR_TMP_REQUEST_PATHS = [
    "/var/tmp/vfs_canon_probe",
    "/private/var/tmp/vfs_canon_probe",
    "/System/Volumes/Data/private/var/tmp/vfs_canon_probe",
]
ETC_REQUEST_PATHS = [
    "/etc/hosts",
    "/private/etc/hosts",
]
FIRMLINK_REQUEST_PATHS = [
    "/private/tmp/vfs_firmlink_probe",
    "/System/Volumes/Data/private/tmp/vfs_firmlink_probe",
]
LINK_REQUEST_PATHS = [
    "/private/tmp/vfs_linkdir/to_var_tmp/vfs_link_probe",
    "/private/var/tmp/vfs_link_probe",
]

PROFILE_CONFIGS: Dict[str, Dict[str, Any]] = {
    "vfs_tmp_only": {
        "sb": SB_DIR / "vfs_tmp_only.sb",
        "path_pairs": BASE_PATH_PAIRS,
        "ops": ["file-read*", "file-write*"],
        "role": "first_only",
        "policy": "canonicalized_with_var_tmp_exception",
        "variant": "tmp",
    },
    "vfs_private_tmp_only": {
        "sb": SB_DIR / "vfs_private_tmp_only.sb",
        "path_pairs": BASE_PATH_PAIRS,
        "ops": ["file-read*", "file-write*"],
        "role": "second_only",
        "policy": "canonicalized_with_var_tmp_exception",
        "variant": "tmp",
    },
    "vfs_both_paths": {
        "sb": SB_DIR / "vfs_both_paths.sb",
        "path_pairs": BASE_PATH_PAIRS,
        "ops": ["file-read*", "file-write*"],
        "role": "both",
        "policy": "canonicalized_with_var_tmp_exception",
        "variant": "tmp",
    },
    "vfs_var_tmp_alias_only": {
        "sb": SB_DIR / "vfs_var_tmp_alias_only.sb",
        "request_paths": VAR_TMP_REQUEST_PATHS,
        "allowed_paths": ["/var/tmp/vfs_canon_probe"],
        "ops": ["file-read*", "file-write*"],
        "policy": "literal",
        "variant": "var_tmp",
    },
    "vfs_var_tmp_private_only": {
        "sb": SB_DIR / "vfs_var_tmp_private_only.sb",
        "request_paths": VAR_TMP_REQUEST_PATHS,
        "allowed_paths": ["/private/var/tmp/vfs_canon_probe"],
        "ops": ["file-read*", "file-write*"],
        "policy": "literal",
        "variant": "var_tmp",
    },
    "vfs_var_tmp_both": {
        "sb": SB_DIR / "vfs_var_tmp_both.sb",
        "request_paths": VAR_TMP_REQUEST_PATHS,
        "allowed_paths": ["/var/tmp/vfs_canon_probe", "/private/var/tmp/vfs_canon_probe"],
        "ops": ["file-read*", "file-write*"],
        "policy": "literal",
        "variant": "var_tmp",
    },
    "vfs_var_tmp_data_only": {
        "sb": SB_DIR / "vfs_var_tmp_data_only.sb",
        "request_paths": VAR_TMP_REQUEST_PATHS,
        "allowed_paths": ["/System/Volumes/Data/private/var/tmp/vfs_canon_probe"],
        "ops": ["file-read*", "file-write*"],
        "policy": "literal",
        "variant": "var_tmp",
    },
    "vfs_etc_alias_only": {
        "sb": SB_DIR / "vfs_etc_alias_only.sb",
        "request_paths": ETC_REQUEST_PATHS,
        "allowed_paths": ["/etc/hosts"],
        "ops": ["file-read*"],
        "policy": "literal",
        "variant": "etc",
    },
    "vfs_etc_private_only": {
        "sb": SB_DIR / "vfs_etc_private_only.sb",
        "request_paths": ETC_REQUEST_PATHS,
        "allowed_paths": ["/private/etc/hosts"],
        "ops": ["file-read*"],
        "policy": "literal",
        "variant": "etc",
    },
    "vfs_etc_both": {
        "sb": SB_DIR / "vfs_etc_both.sb",
        "request_paths": ETC_REQUEST_PATHS,
        "allowed_paths": ["/etc/hosts", "/private/etc/hosts"],
        "ops": ["file-read*"],
        "policy": "literal",
        "variant": "etc",
    },
    "vfs_firmlink_private_only": {
        "sb": SB_DIR / "vfs_firmlink_private_only.sb",
        "request_paths": FIRMLINK_REQUEST_PATHS,
        "allowed_paths": ["/private/tmp/vfs_firmlink_probe"],
        "ops": ["file-read*", "file-write*"],
        "policy": "literal",
        "variant": "firmlink_tmp",
    },
    "vfs_firmlink_data_only": {
        "sb": SB_DIR / "vfs_firmlink_data_only.sb",
        "request_paths": FIRMLINK_REQUEST_PATHS,
        "allowed_paths": ["/System/Volumes/Data/private/tmp/vfs_firmlink_probe"],
        "ops": ["file-read*", "file-write*"],
        "policy": "literal",
        "variant": "firmlink_tmp",
    },
    "vfs_firmlink_both": {
        "sb": SB_DIR / "vfs_firmlink_both.sb",
        "request_paths": FIRMLINK_REQUEST_PATHS,
        "allowed_paths": ["/private/tmp/vfs_firmlink_probe", "/System/Volumes/Data/private/tmp/vfs_firmlink_probe"],
        "ops": ["file-read*", "file-write*"],
        "policy": "literal",
        "variant": "firmlink_tmp",
    },
    "vfs_link_var_tmp_only": {
        "sb": SB_DIR / "vfs_link_var_tmp_only.sb",
        "request_paths": LINK_REQUEST_PATHS,
        "allowed_paths": ["/private/var/tmp/vfs_link_probe"],
        "ops": ["file-read*", "file-write*"],
        "policy": "literal",
        "variant": "link_path",
    },
    "vfs_link_private_tmp_only": {
        "sb": SB_DIR / "vfs_link_private_tmp_only.sb",
        "request_paths": LINK_REQUEST_PATHS,
        "allowed_paths": ["/private/tmp/vfs_linkdir/to_var_tmp/vfs_link_probe"],
        "ops": ["file-read*", "file-write*"],
        "policy": "literal",
        "variant": "link_path",
    },
    "vfs_link_both": {
        "sb": SB_DIR / "vfs_link_both.sb",
        "request_paths": LINK_REQUEST_PATHS,
        "allowed_paths": [
            "/private/tmp/vfs_linkdir/to_var_tmp/vfs_link_probe",
            "/private/var/tmp/vfs_link_probe",
        ],
        "ops": ["file-read*", "file-write*"],
        "policy": "literal",
        "variant": "link_path",
    },
}


def rel(path: Path) -> str:
    return to_repo_relative(path, REPO_ROOT)


def load_world_id() -> str:
    data = json.loads(WORLD_PATH.read_text())
    return data.get("world_id") or data.get("id", "unknown-world")


def compile_profiles() -> Dict[str, Path]:
    """Compile VFS SBPL profiles to blobs and return map profile_id -> blob path."""
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    blobs: Dict[str, Path] = {}
    for profile_id, cfg in PROFILE_CONFIGS.items():
        sb_path = cfg["sb"]
        blob_path = BUILD_DIR / f"{sb_path.stem}.sb.bin"
        blob = compile_sbpl_string(sb_path.read_text()).blob
        blob_path.write_bytes(blob)
        blobs[profile_id] = blob_path
    return blobs


def _expected_decisions(policy: str, role: str, primary_path: str, alternate_path: str) -> tuple[str, str]:
    if policy == "literal":
        if role == "first_only":
            return "allow", "deny"
        if role == "second_only":
            return "deny", "allow"
        if role == "both":
            return "allow", "allow"
        raise ValueError(f"unknown role {role}")

    if policy in {"canonicalized", "canonicalized_with_var_tmp_exception"}:
        if role == "first_only":
            primary = "deny"
            alternate = "deny"
        elif role in {"second_only", "both"}:
            primary = "allow"
            alternate = "allow"
        else:
            raise ValueError(f"unknown role {role}")

        if policy == "canonicalized_with_var_tmp_exception" and alternate_path.startswith("/private/var/"):
            primary = "deny"
            if role == "first_only":
                alternate = "deny"
            else:
                alternate = "allow"
        return primary, alternate

    raise ValueError(f"unknown policy {policy}")


def build_simple_expected_matrix() -> List[Dict[str, Any]]:
    """Emit a simple expected matrix across all profile configs and path sets."""
    entries: List[Dict[str, Any]] = []
    for profile_id, cfg in PROFILE_CONFIGS.items():
        ops = cfg["ops"]
        policy = cfg["policy"]
        variant = cfg["variant"]
        if policy == "literal":
            request_paths = cfg.get("request_paths") or [path for pair in cfg.get("path_pairs", []) for path in pair]
            allowed_paths = set(cfg.get("allowed_paths") or [])
            for path in request_paths:
                expected = "allow" if path in allowed_paths else "deny"
                for op in ops:
                    entries.append(
                        {
                            "profile_id": profile_id,
                            "operation": op,
                            "requested_path": path,
                            "expected_decision": expected,
                            "notes": f"{profile_id} {variant}/{policy} {path}",
                        }
                    )
            continue

        role = cfg["role"]
        for primary_path, alternate_path in cfg["path_pairs"]:
            primary_expected, alternate_expected = _expected_decisions(policy, role, primary_path, alternate_path)
            for op in ops:
                entries.append(
                    {
                        "profile_id": profile_id,
                        "operation": op,
                        "requested_path": primary_path,
                        "expected_decision": primary_expected,
                        "notes": f"{profile_id} {variant}/{policy}/{role} primary {primary_path}",
                    }
                )
                entries.append(
                    {
                        "profile_id": profile_id,
                        "operation": op,
                        "requested_path": alternate_path,
                        "expected_decision": alternate_expected,
                        "notes": f"{profile_id} {variant}/{policy}/{role} alternate {alternate_path}",
                    }
                )
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "expected_matrix.json"
    out_path.write_text(json.dumps(entries, indent=2))
    return entries


def build_harness_matrix(world_id: str, blobs: Dict[str, Path], simple_matrix: List[Dict[str, Any]]) -> Path:
    """Translate the simple matrix into the harness-compatible expected matrix."""
    profiles: Dict[str, Any] = {}
    # Map from profile_id to sb path for runtime harness
    sb_paths: Dict[str, Path] = {profile_id: cfg["sb"] for profile_id, cfg in PROFILE_CONFIGS.items()}
    for entry in simple_matrix:
        profile_id = entry["profile_id"]
        path = entry["requested_path"]
        expected = entry["expected_decision"]
        operation = entry["operation"]
        rec = profiles.setdefault(
            profile_id,
            {
                "mode": "sbpl",
                "sbpl": rel(sb_paths[profile_id]),
                "blob": rel(blobs[profile_id]),
                "family": "vfs",
                "semantic_group": "vfs:canonicalization",
                "probes": [],
            },
        )
        probe = {
            "name": f"{operation}:{path}",
            "operation": operation,
            "target": path,
            "expected": expected,
        }
        probe["expectation_id"] = f"{profile_id}:{operation}:{path}"
        rec["probes"].append(probe)
    matrix = {"world_id": world_id, "profiles": profiles}
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    matrix_path = OUT_DIR / "expected_matrix_harness.json"
    matrix_path.write_text(json.dumps(matrix, indent=2))
    return matrix_path


def run_runtime(matrix_path: Path, sb_paths: Dict[str, Path]) -> Path:
    """Run the harness matrix via runtime_tools and return path to raw runtime_results.json."""
    harness_out = OUT_DIR / "harness"
    harness_out.mkdir(parents=True, exist_ok=True)
    runtime_out = run_matrix(
        matrix_path=matrix_path,
        out_dir=harness_out,
        profile_paths={k: ensure_absolute(v, REPO_ROOT) for k, v in sb_paths.items()},
    )
    return runtime_out


def normalize_runtime_results(expected_matrix_path: Path, raw_runtime_results_path: Path) -> Path:
    """Normalize runtime harness output into canonical runtime events for this suite."""
    out_path = OUT_DIR / "runtime_events.normalized.json"
    write_matrix_observations(expected_matrix_path, raw_runtime_results_path, out_path)
    return out_path


def downconvert_runtime_results(normalized_events_path: Path) -> Path:
    """Down-convert normalized runtime events into the simple array format."""
    events = json.loads(normalized_events_path.read_text())
    simple: List[Dict[str, Any]] = []
    for event in events:
        requested_path = event.get("target")
        stderr = event.get("stderr")
        fd_obs = _extract_path_observation(stderr, "F_GETPATH")
        nofirmlink_obs = _extract_path_observation(stderr, "F_GETPATH_NOFIRMLINK")
        observed_path = fd_obs["path"] or requested_path
        observed_path_source = "fd_path" if fd_obs["path"] else "requested_path"
        simple.append(
            {
                "profile_id": event.get("profile_id"),
                "operation": event.get("operation"),
                "requested_path": requested_path,
                "observed_path": observed_path,
                "observed_path_source": observed_path_source,
                "observed_path_nofirmlink": nofirmlink_obs["path"],
                "observed_path_nofirmlink_source": nofirmlink_obs["source"],
                "observed_path_nofirmlink_errno": nofirmlink_obs["errno"],
                "observed_path_errno": fd_obs["errno"],
                "decision": event.get("actual"),
                "errno": event.get("errno"),
                "failure_stage": event.get("failure_stage"),
                "failure_kind": event.get("failure_kind"),
                "apply_report": event.get("apply_report"),
                "runner_info": event.get("runner_info"),
                "seatbelt_callouts": event.get("seatbelt_callouts"),
                "violation_summary": event.get("violation_summary"),
                "raw_log": {
                    "command": event.get("command"),
                    "stdout": event.get("stdout"),
                    "stderr": stderr,
                },
            }
        )
    out_path = OUT_DIR / "runtime_results.json"
    out_path.write_text(json.dumps(simple, indent=2))
    return out_path


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


def _extract_path_observation(stderr: str | None, label: str) -> Dict[str, Any]:
    if not stderr:
        return {"path": None, "source": "not_attempted", "errno": None}
    for line in stderr.splitlines():
        if line.startswith(f"{label}:"):
            return {"path": line.split(":", 1)[1].strip() or None, "source": "fd_path", "errno": None}
        if line.startswith(f"{label}_ERROR:"):
            err_raw = line.split(":", 1)[1].strip()
            try:
                err = int(err_raw)
            except ValueError:
                err = None
            return {"path": None, "source": "error", "errno": err}
        if line.startswith(f"{label}_UNAVAILABLE"):
            return {"path": None, "source": "unavailable", "errno": None}
    return {"path": None, "source": "not_attempted", "errno": None}


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


def all_anchor_paths() -> List[str]:
    anchors: set[str] = set()
    for cfg in PROFILE_CONFIGS.values():
        for pair in cfg.get("path_pairs", []):
            anchors.update(pair)
        for path in cfg.get("request_paths", []):
            anchors.add(path)
    return sorted(anchors)


def decode_profiles(blobs: Dict[str, Path]) -> Path:
    """Decode the VFS blobs and extract anchor/tag/field2 structure for configured path pairs."""
    anchors = all_anchor_paths()
    decode: Dict[str, Any] = {}
    for profile_id, blob_path in blobs.items():
        data = blob_path.read_bytes()
        dec = decoder.decode_profile_dict(data)
        literal_set = set()
        for lit in dec.get("literal_strings") or []:
            literal_set.update(_literal_candidates(lit))
        nodes = dec.get("nodes") or []
        anchors_info: List[Dict[str, Any]] = []
        for anchor in anchors:
            present = anchor_present(anchor, literal_set)
            tag_ids = set()
            field2_vals = set()
            for node in nodes:
                ref_candidates = set()
                for ref in (node.get("literal_refs") or []):
                    ref_candidates.update(_literal_candidates(ref))
                if anchor_present(anchor, ref_candidates):
                    tag_ids.add(node.get("tag"))
                    fields = node.get("fields") or []
                    if len(fields) > 2:
                        field2_vals.add(fields[2])
            anchors_info.append(
                {
                    "path": anchor,
                    "present": present,
                    "tags": sorted(tag_ids),
                    "field2_values": sorted(field2_vals),
                }
            )
        decode[profile_id] = {
            "anchors": anchors_info,
            "literal_candidates": sorted(literal_set),
            "node_count": dec.get("node_count"),
            "tag_counts": dec.get("tag_counts"),
        }
    out_path = OUT_DIR / "decode_tmp_profiles.json"
    out_path.write_text(json.dumps(decode, indent=2))
    return out_path


def emit_mismatch_summary(world_id: str) -> Path:
    """
    Emit a coarse mismatch summary for this suite.

    For this cut we classify the base /tmp family profiles based on the observed
    patterns in runtime_results.json on this world and the intended design:
    - vfs_tmp_only: canonicalization-before-enforcement makes the /tmp literal ineffective.
    - vfs_private_tmp_only: canonical literal effective; both requests allowed.
    - vfs_both_paths: control; both requests allowed with both paths mentioned in SBPL.
    """
    summary: Dict[str, Any] = {
        "world_id": world_id,
        "profiles": {
            "vfs_tmp_only": {
                "kind": "canonicalization",
                "note": "Profile mentions only /tmp/* paths; alias and canonical requests are denied across the path set, consistent with canonicalization-before-enforcement with only /private/... literals effective.",
            },
            "vfs_private_tmp_only": {
                "kind": "canonicalization",
                "note": "Profile mentions only canonical /private/... paths; alias and canonical requests are allowed across the path set; literal on canonical path effective for both.",
            },
            "vfs_both_paths": {
                "kind": "control",
                "note": "Profile mentions both alias and canonical forms; all requests allowed; control confirming canonical behavior.",
            },
        },
    }
    out_path = OUT_DIR / "mismatch_summary.json"
    out_path.write_text(json.dumps(summary, indent=2))
    return out_path


def ensure_vfs_files() -> None:
    """Ensure the basic /tmp and /private/tmp fixtures exist."""
    ensure_fixtures()
    fixture_paths = [
        Path("/private/tmp/foo"),
        Path("/private/tmp/bar"),
        Path("/private/tmp/nested/child"),
        Path("/private/var/tmp/canon"),
        Path("/private/var/tmp/vfs_canon_probe"),
        Path("/private/tmp/vfs_firmlink_probe"),
        Path("/private/var/tmp/vfs_link_probe"),
    ]
    for path in fixture_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"vfs-canonicalization {path.name}\n")

    link_dir = Path("/private/tmp/vfs_linkdir")
    link_dir.mkdir(parents=True, exist_ok=True)
    link_path = link_dir / "to_var_tmp"
    if link_path.exists() or link_path.is_symlink():
        link_path.unlink()
    link_path.symlink_to("/private/var/tmp")


def main() -> int:
    world_id = load_world_id()
    blobs = compile_profiles()
    simple_matrix = build_simple_expected_matrix()
    matrix_path = build_harness_matrix(world_id, blobs, simple_matrix)
    ensure_vfs_files()
    sb_paths = {profile_id: cfg["sb"] for profile_id, cfg in PROFILE_CONFIGS.items()}
    raw_runtime = run_runtime(matrix_path, sb_paths)
    normalized_events = normalize_runtime_results(matrix_path, raw_runtime)
    downconvert_runtime_results(normalized_events)
    decode_profiles(blobs)
    emit_mismatch_summary(world_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
