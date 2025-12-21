#!/usr/bin/env python3
"""
Phase 1 adversarial runtime harness.

Builds expected matrices for two families (structural variants, path/literal edges),
compiles SBPL → blob, runs runtime probes via runtime_tools, and emits mismatch summaries.
"""
from __future__ import annotations
import json

import socketserver
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure repository root is on sys.path for `book` imports when run directly.
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import find_repo_root
from book.api.runtime_tools.runtime_pipeline import FamilySpec, run_family_specs, generate_runtime_cut
from book.api.runtime_tools.observations import WORLD_ID, write_normalized_events

REPO_ROOT = find_repo_root(Path(__file__))

BASE_DIR = Path(__file__).resolve().parent
SB_DIR = BASE_DIR / "sb"
BUILD_DIR = SB_DIR / "build"
OUT_DIR = BASE_DIR / "out"
WORLD_PATH = REPO_ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world-baseline.json"
ADVERSARIAL_SUMMARY = REPO_ROOT / "book" / "graph" / "mappings" / "runtime" / "adversarial_summary.json"


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def load_world_id() -> str:
    import json

    data = json.loads(WORLD_PATH.read_text())
    return data.get("world_id") or data.get("id", WORLD_ID)


def ensure_fixture_files() -> None:
    """Create file fixtures used by probes."""
    struct_root = Path("/tmp/runtime-adv/struct")
    edges_root = Path("/tmp/runtime-adv/edges")

    for path in [
        struct_root / "ok" / "allowed.txt",
        struct_root / "ok" / "deep" / "nested.txt",
        struct_root / "blocked.txt",
        struct_root / "outside.txt",
        edges_root / "a",
        edges_root / "okdir" / "item.txt",
        edges_root / "okdir" / ".." / "blocked.txt",
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"runtime-adv fixture for {path}\n")


def start_loopback_server() -> Tuple[socketserver.TCPServer, int]:
    """Start a simple TCP listener on 127.0.0.1 that accepts and replies."""

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            try:
                _ = self.request.recv(16)
                self.request.sendall(b"ok")
            except Exception:
                pass

    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    srv: socketserver.TCPServer = ReusableTCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, srv.server_address[1]


def build_families(loopback_targets: List[str]) -> List[FamilySpec]:
    probes_common_read = [
        {
            "name": "allow-ok-root",
            "operation": "file-read*",
            "target": "/tmp/runtime-adv/struct/ok/allowed.txt",
            "expected": "allow",
        },
        {
            "name": "allow-ok-deep",
            "operation": "file-read*",
            "target": "/tmp/runtime-adv/struct/ok/deep/nested.txt",
            "expected": "allow",
        },
        {
            "name": "deny-blocked",
            "operation": "file-read*",
            "target": "/tmp/runtime-adv/struct/blocked.txt",
            "expected": "deny",
        },
        {
            "name": "deny-outside",
            "operation": "file-read*",
            "target": "/tmp/runtime-adv/struct/outside.txt",
            "expected": "deny",
        },
    ]
    probes_common_write = [
        {
            "name": "write-ok-root",
            "operation": "file-write*",
            "target": "/tmp/runtime-adv/struct/ok/allowed.txt",
            "expected": "allow",
        },
        {
            "name": "write-ok-deep",
            "operation": "file-write*",
            "target": "/tmp/runtime-adv/struct/ok/deep/nested.txt",
            "expected": "allow",
        },
        {
            "name": "write-blocked",
            "operation": "file-write*",
            "target": "/tmp/runtime-adv/struct/blocked.txt",
            "expected": "deny",
        },
        {
            "name": "write-outside",
            "operation": "file-write*",
            "target": "/tmp/runtime-adv/struct/outside.txt",
            "expected": "deny",
        },
    ]
    probes_edges_read = [
        {
            "name": "allow-tmp",
            "operation": "file-read*",
            "target": "/tmp/runtime-adv/edges/a",
            "expected": "allow",
        },
        {
            "name": "deny-private",
            "operation": "file-read*",
            "target": "/private/tmp/runtime-adv/edges/a",
            "expected": "deny",
        },
        {
            "name": "allow-subpath",
            "operation": "file-read*",
            "target": "/tmp/runtime-adv/edges/okdir/item.txt",
            "expected": "allow",
        },
        {
            "name": "deny-dotdot",
            "operation": "file-read*",
            "target": "/tmp/runtime-adv/edges/okdir/../blocked.txt",
            "expected": "deny",
        },
    ]
    probes_edges_write = [
        {
            "name": "write-tmp",
            "operation": "file-write*",
            "target": "/tmp/runtime-adv/edges/a",
            "expected": "allow",
        },
        {
            "name": "write-private",
            "operation": "file-write*",
            "target": "/private/tmp/runtime-adv/edges/a",
            "expected": "deny",
        },
        {
            "name": "write-subpath",
            "operation": "file-write*",
            "target": "/tmp/runtime-adv/edges/okdir/item.txt",
            "expected": "allow",
        },
        {
            "name": "write-dotdot",
            "operation": "file-write*",
            "target": "/tmp/runtime-adv/edges/okdir/../blocked.txt",
            "expected": "deny",
        },
    ]

    probes_mach = [
        {
            "name": "allow-cfprefsd",
            "operation": "mach-lookup",
            "target": "com.apple.cfprefsd.agent",
            "expected": "allow",
        },
        {
            "name": "deny-bogus",
            "operation": "mach-lookup",
            "target": "com.apple.sandboxadversarial.fake",
            "expected": "deny",
        },
    ]
    probes_mach_local = [
        {
            "name": "allow-cfprefsd-local",
            "operation": "mach-lookup",
            "target": "com.apple.cfprefsd.agent",
            "expected": "allow",
            "mode": "local",
        },
        {
            "name": "deny-bogus-local",
            "operation": "mach-lookup",
            "target": "com.apple.sandboxadversarial.fake",
            "expected": "deny",
            "mode": "local",
        },
    ]

    probes_net_allow = []
    probes_net_deny = []
    for idx, target in enumerate(loopback_targets or ["127.0.0.1"]):
        name = "tcp-loopback" if idx == 0 else f"tcp-loopback-{idx+1}"
        probes_net_allow.append({"name": name, "operation": "network-outbound", "target": target, "expected": "allow"})
        probes_net_deny.append({"name": name, "operation": "network-outbound", "target": target, "expected": "deny"})

    return [
        FamilySpec(
            profile_id="adv:struct_flat",
            profile_path=SB_DIR / "struct_flat.sb",
            probes=probes_common_read + probes_common_write,
            family="structural_variants",
            semantic_group="structural:file-read-subpath",
        ),
        FamilySpec(
            profile_id="adv:struct_nested",
            profile_path=SB_DIR / "struct_nested.sb",
            probes=probes_common_read + probes_common_write,
            family="structural_variants",
            semantic_group="structural:file-read-subpath",
        ),
        FamilySpec(
            profile_id="adv:path_edges",
            profile_path=SB_DIR / "path_edges.sb",
            probes=probes_edges_read + probes_edges_write,
            family="path_edges",
            semantic_group="paths:literal-vs-normalized",
        ),
        FamilySpec(
            profile_id="adv:mach_simple_allow",
            profile_path=SB_DIR / "mach_simple_allow.sb",
            probes=probes_mach,
            family="mach_variants",
            semantic_group="mach:global-name-allow",
        ),
        FamilySpec(
            profile_id="adv:mach_simple_variants",
            profile_path=SB_DIR / "mach_simple_variants.sb",
            probes=probes_mach,
            family="mach_variants",
            semantic_group="mach:global-name-allow",
        ),
        FamilySpec(
            profile_id="adv:mach_local_literal",
            profile_path=SB_DIR / "mach_local_literal.sb",
            probes=probes_mach_local,
            family="mach_local",
            semantic_group="mach:local-name-allow",
        ),
        FamilySpec(
            profile_id="adv:mach_local_regex",
            profile_path=SB_DIR / "mach_local_regex.sb",
            probes=probes_mach_local,
            family="mach_local",
            semantic_group="mach:local-name-allow",
        ),
        FamilySpec(
            profile_id="adv:net_outbound_allow",
            profile_path=SB_DIR / "net_outbound_allow.sb",
            probes=probes_net_allow,
            family="network",
            semantic_group="network:outbound-allow",
        ),
        FamilySpec(
            profile_id="adv:net_outbound_deny",
            profile_path=SB_DIR / "net_outbound_deny.sb",
            probes=probes_net_deny,
            family="network",
            semantic_group="network:outbound-deny",
        ),
    ]


def update_adversarial_summary(world_id: str, matrix: Dict[str, Any], summary: Dict[str, Any]) -> None:
    rows = {
        "world_id": world_id,
        "profiles": len(matrix.get("profiles") or {}),
        "expectations": sum(len(p.get("probes") or []) for p in (matrix.get("profiles") or {}).values()),
        "mismatch_counts": summary.get("counts") or {},
    }
    write_json(ADVERSARIAL_SUMMARY, rows)


def main() -> int:
    world_id = load_world_id()
    ensure_fixture_files()
    loopback_srvs: List[socketserver.TCPServer] = []
    loopback_targets: List[str] = []
    try:
        srv1, port1 = start_loopback_server()
        loopback_srvs.append(srv1)
        loopback_targets.append(f"127.0.0.1:{port1}")
        srv2, port2 = start_loopback_server()
        loopback_srvs.append(srv2)
        loopback_targets.append(f"127.0.0.1:{port2}")
    except Exception:
        loopback_srvs = []
        loopback_targets = []

    families = build_families(loopback_targets)
    artifacts = run_family_specs(families, OUT_DIR, world_id=world_id)
    matrix_path = artifacts.get("expected_matrix") or OUT_DIR / "expected_matrix.generated.json"
    runtime_out = artifacts.get("runtime_results") or OUT_DIR / "runtime_results.json"

    # Keep compatibility filenames for downstream consumers during transition.
    if matrix_path.exists():
        (OUT_DIR / "expected_matrix.json").write_text(Path(matrix_path).read_text())
    if runtime_out.exists():
        (OUT_DIR / "runtime_results.json").write_text(Path(runtime_out).read_text())
    mismatch_doc = {}
    if artifacts.get("mismatch_summary"):
        mismatch_doc = json.loads(Path(artifacts["mismatch_summary"]).read_text())
        (OUT_DIR / "mismatch_summary.json").write_text(json.dumps(mismatch_doc, indent=2))
    impact_map = OUT_DIR / "impact_map.json"
    impact_body: Dict[str, Any] = {}
    for mismatch in mismatch_doc.get("mismatches") or []:
        eid = mismatch.get("expectation_id")
        if not eid:
            continue
        entry = {
            "world_id": world_id,
            "profile_id": mismatch.get("profile_id"),
            "operation": mismatch.get("operation"),
            "mismatch_type": mismatch.get("mismatch_type"),
            "notes": mismatch.get("notes"),
            "path": mismatch.get("path"),
        }
        if mismatch.get("violation_summary") == "EPERM":
            entry["tags"] = ["apply_gate"]
        impact_body[eid] = entry
    impact_map.write_text(json.dumps(impact_body, indent=2))

    try:
        events_path = OUT_DIR / "runtime_events.normalized.json"
        write_normalized_events(matrix_path, runtime_out, events_path, world_id=world_id)
        print(f"[+] wrote normalized events to {events_path}")
        print(f"[+] runtime mapping set under {OUT_DIR / 'runtime_mappings'} -> {artifacts}")
    except Exception as e:
        print(f"[!] failed to normalize runtime events: {e}")

    matrix_doc = json.loads(Path(matrix_path).read_text())
    summary_doc = json.loads((OUT_DIR / "mismatch_summary.json").read_text()) if (OUT_DIR / "mismatch_summary.json").exists() else {}
    update_adversarial_summary(world_id, matrix_doc, summary_doc)
    for srv in loopback_srvs:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
