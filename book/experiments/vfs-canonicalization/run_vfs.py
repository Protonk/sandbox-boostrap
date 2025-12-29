#!/usr/bin/env python3
"""
VFS canonicalization harness for alias/canonical path families on Sonoma.

Tasks:
- Ensure local fixtures for the VFS probes.
- Run the plan-based runtime harness.
- Down-convert normalized runtime events into a simple runtime_results.json array.
- Decode the compiled SBPL blobs and emit decode_tmp_profiles.json
  (anchors, tags, and field2 values for the configured path pairs).
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List
import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils
from book.api.profile_tools import compile_sbpl_string, decoder  # type: ignore
from book.api.runtime.execution import service as runtime_api  # type: ignore
from book.api.runtime.plans import builder as runtime_plan_builder  # type: ignore
from book.api.runtime.plans import registry as runtime_registry  # type: ignore
from book.api.runtime.execution.channels import ChannelSpec  # type: ignore
from book.api.runtime.execution.harness.runner import ensure_fixtures  # type: ignore


REPO_ROOT = path_utils.find_repo_root(Path(__file__))
BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "out"
PLAN_PATH = BASE_DIR / "plan.json"
REGISTRY_ID = "vfs-canonicalization"
TEMPLATE_ID = "vfs-canonicalization"
WORLD_PATH = REPO_ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def load_world_id() -> str:
    data = _load_json(WORLD_PATH)
    return data.get("world_id") or data.get("id", "unknown-world")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run VFS canonicalization via runtime plan.")
    parser.add_argument("--out", type=Path, default=OUT_DIR, help="Output directory")
    parser.add_argument("--channel", type=str, default="launchd_clean", help="Channel (launchd_clean|direct)")
    parser.add_argument(
        "--require-promotable",
        action="store_true",
        help="Fail unless the resulting bundle is decision-stage promotable (recommended for launchd_clean).",
    )
    return parser.parse_args()


def load_plan_doc() -> Dict[str, Any]:
    if not PLAN_PATH.exists():
        raise FileNotFoundError("missing plan.json; run runtime plan-build first")
    return _load_json(PLAN_PATH)


def load_profile_paths(plan_doc: Dict[str, Any]) -> Dict[str, Path]:
    registry = runtime_registry.load_registry(REGISTRY_ID)
    profiles = registry.get("profiles") or {}
    paths: Dict[str, Path] = {}
    for profile_id in plan_doc.get("profiles") or []:
        profile = profiles.get(profile_id)
        if not profile:
            raise KeyError(f"profile not found in registry: {REGISTRY_ID}:{profile_id}")
        profile_path = profile.get("profile_path")
        if not profile_path:
            raise KeyError(f"profile missing profile_path: {REGISTRY_ID}:{profile_id}")
        paths[profile_id] = path_utils.ensure_absolute(Path(profile_path), REPO_ROOT)
    return paths


def resolve_blob_paths(profile_paths: Dict[str, Path], bundle_dir: Path) -> Dict[str, Path]:
    build_dir = bundle_dir / "sb_build"
    build_dir.mkdir(parents=True, exist_ok=True)
    blobs: Dict[str, Path] = {}
    for profile_id, sbpl_path in profile_paths.items():
        blob_path = build_dir / f"{sbpl_path.stem}.sb.bin"
        if not blob_path.exists():
            blob = compile_sbpl_string(sbpl_path.read_text()).blob
            blob_path.write_bytes(blob)
        blobs[profile_id] = blob_path
    return blobs


def run_runtime_plan(out_dir: Path, channel_name: str) -> Path:
    channel = ChannelSpec(channel=channel_name, require_clean=(channel_name == "launchd_clean"))
    bundle = runtime_api.run_plan(PLAN_PATH, out_dir, channel=channel)
    if bundle.status == "failed":
        raise RuntimeError(f"runtime plan failed; see {bundle.out_dir / 'run_status.json'}")
    return bundle.out_dir


def downconvert_runtime_results(normalized_events_path: Path) -> Path:
    """Down-convert normalized runtime events into the simple array format."""
    events = json.loads(normalized_events_path.read_text())
    witness_map: Dict[tuple[str, str, str], Dict[str, Any]] = {}
    witness_path = normalized_events_path.parent / "path_witnesses.json"
    if witness_path.exists():
        witness_doc = json.loads(witness_path.read_text())
        for rec in witness_doc.get("records") or []:
            if rec.get("lane") != "scenario":
                continue
            profile_id = rec.get("profile_id")
            op = rec.get("operation")
            requested = rec.get("requested_path")
            if not profile_id or not op or not requested:
                continue
            witness_map[(profile_id, op, requested)] = rec
    simple: List[Dict[str, Any]] = []
    for event in events:
        requested_path = event.get("target")
        stderr = event.get("stderr")
        witness = None
        if event.get("profile_id") and event.get("operation") and requested_path:
            witness = witness_map.get((event["profile_id"], event["operation"], requested_path))

        if witness:
            fd_path = witness.get("observed_path")
            nofirmlink_path = witness.get("observed_path_nofirmlink")
            fd_obs = {"path": fd_path, "source": witness.get("observed_path_source"), "errno": witness.get("observed_path_errno")}
            nofirmlink_obs = {
                "path": nofirmlink_path,
                "source": witness.get("observed_path_nofirmlink_source"),
                "errno": witness.get("observed_path_nofirmlink_errno"),
            }
        else:
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


def decode_profiles(blobs: Dict[str, Path], anchors: List[str]) -> Path:
    """Decode the VFS blobs and extract anchor/tag/field2 structure for configured path pairs."""
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
    args = parse_args()
    plan_doc = load_plan_doc()
    world_id = load_world_id()

    ensure_vfs_files()
    bundle_dir = run_runtime_plan(args.out, args.channel)

    normalized_events = bundle_dir / "runtime_events.normalized.json"
    if not normalized_events.exists():
        raise FileNotFoundError(f"missing runtime events: {normalized_events}")
    shutil.copyfile(normalized_events, OUT_DIR / "runtime_events.normalized.json")
    downconvert_runtime_results(normalized_events)

    packet_out = Path(args.out) / "promotion_packet.json"
    runtime_api.emit_promotion_packet(
        Path(args.out),
        packet_out,
        require_promotable=bool(args.require_promotable),
    )

    template = runtime_plan_builder.load_plan_template(TEMPLATE_ID)
    anchors = runtime_plan_builder.collect_anchor_paths(template)
    profile_paths = load_profile_paths(plan_doc)
    blobs = resolve_blob_paths(profile_paths, bundle_dir)
    decode_profiles(blobs, anchors)

    emit_mismatch_summary(world_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
