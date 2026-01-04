"""
Runtime tooling inventory builder.

Collects in-repo runtime tooling references plus a curated external list.

The inventory acts as a map of "where runtime evidence lives" so
agents can route questions without spelunking the repo tree.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from book.api import path_utils


REPO_ROOT = path_utils.find_repo_root(Path(__file__))
BASELINE = REPO_ROOT / "book/world/sonoma-14.4.1-23E224-arm64/world.json"
SCHEMA_VERSION = "hardened-runtime.other-runtime-inventory.v0.1"

# Keyword scan targets common runtime/sandbox tokens for cross-repo discovery.
KEYWORDS = [
    "sandbox_init",
    "sandbox_init_with_parameters",
    "sandbox_apply",
    "sandbox_check",
    "sandbox_extension_",
    "seatbelt",
    "SBPL",
    "sandboxd",
    "com.apple.sandbox.reporting",
    "EndpointSecurity",
    "es_subscribe",
    "auditd",
    "OpenBSM",
    "dtrace",
    "frida",
    "policy-witness",
    "PolicyWitness",
]
EXCLUDED_SCAN_PREFIXES = (
    "book/evidence/experiments/archive/",
)

IN_REPO_ITEMS: List[Dict[str, Any]] = [
    {
        "id": "runtime-checks",
        "paths": ["book/evidence/experiments/runtime-final-final/suites/runtime-checks"],
        "category": "decision-stage",
        "description": "Decision-stage runtime matrix for bucket/system profiles via sandbox_runner/wrapper.",
        "privileges": "user (launchd clean recommended)",
        "evidence_role": "decision-stage",
        "status": "active",
    },
    {
        "id": "runtime-adversarial",
        "paths": ["book/evidence/experiments/runtime-final-final/suites/runtime-adversarial"],
        "category": "decision-stage",
        "description": "Decision-stage adversarial probes (path edges, flow-divert, mach, net).",
        "privileges": "user (launchd clean required)",
        "evidence_role": "decision-stage",
        "status": "paused",
    },
    {
        "id": "sbpl-graph-runtime",
        "paths": ["book/evidence/experiments/runtime-final-final/suites/sbpl-graph-runtime", "book/evidence/profiles/golden-triple"],
        "category": "decision-stage",
        "description": "Golden triples: SBPL ↔ PolicyGraph ↔ runtime outcomes for selected profiles.",
        "privileges": "user",
        "evidence_role": "decision-stage",
        "status": "partial",
    },
    {
        "id": "runtime-mac_policy",
        "paths": ["book/evidence/experiments/runtime-final-final/suites/nonbaseline/runtime-mac_policy"],
        "category": "tracing",
        "description": "Runtime MACF policy registration tracing via DTrace/FBT on a separate runtime host.",
        "privileges": "root, SIP disabled (runtime-only world)",
        "evidence_role": "tracing",
        "status": "blocked",
    },
    {
        "id": "sandbox-init-params",
        "paths": ["book/evidence/experiments/profile-pipeline/sandbox-init-params"],
        "category": "apply-stage",
        "description": "Investigates sandbox_init_with_parameters plumbing and __sandbox_ms argument layout.",
        "privileges": "user",
        "evidence_role": "apply-stage",
        "status": "active",
    },
    {
        "id": "metadata-runner",
        "paths": ["book/evidence/experiments/runtime-final-final/suites/metadata-runner"],
        "category": "decision-stage",
        "description": "Swift-based metadata syscalls under sandbox_init to probe metadata canonicalization.",
        "privileges": "user",
        "evidence_role": "decision-stage",
        "status": "partial",
    },
    {
        "id": "vfs-canonicalization",
        "paths": ["book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization"],
        "category": "decision-stage",
        "description": "Path alias/canonicalization runtime probes for VFS operations.",
        "privileges": "user",
        "evidence_role": "decision-stage",
        "status": "partial",
    },
    {
        "id": "dtrace-testing",
        "paths": ["book/evidence/experiments/runtime-final-final/suites/dtrace-testing"],
        "category": "tracing",
        "description": "DTrace-based runtime instrumentation experiments.",
        "privileges": "root, SIP disabled",
        "evidence_role": "tracing",
        "status": "ongoing",
    },
    {
        "id": "frida-testing",
        "paths": ["book/evidence/experiments/runtime-final-final/suites/frida-testing"],
        "category": "tracing",
        "description": "Frida-based runtime instrumentation experiments.",
        "privileges": "user (Frida attach; may require entitlements)",
        "evidence_role": "tracing",
        "status": "ongoing",
    },
    {
        "id": "runtime-mappings",
        "paths": ["book/integration/carton/bundle/relationships/mappings/runtime", "book/integration/carton/bundle/relationships/mappings/runtime_cuts"],
        "category": "mapping",
        "description": "Canonical runtime mappings (signatures, coverage, story, traces).",
        "privileges": "n/a (derived)",
        "evidence_role": "mapping-only",
        "status": "active",
    },
    {
        "id": "runtime-tools-api",
        "paths": ["book/api/runtime"],
        "category": "tooling",
        "description": "Shared runtime harness, normalization, and mapping tooling.",
        "privileges": "user",
        "evidence_role": "tooling",
        "status": "active",
    },
    {
        "id": "preflight-tools",
        "paths": ["book/tools/preflight", "book/tools/preflight/index", "book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests"],
        "category": "apply-stage",
        "description": "Apply-gate preflight scanning and enterability indices.",
        "privileges": "user",
        "evidence_role": "apply-stage",
        "status": "active",
    },
    {
        "id": "policy-witness",
        "paths": ["book/tools/witness", "book/api/witness"],
        "category": "logging",
        "description": "App Sandbox/entitlement probes and sandbox log observation (PolicyWitness).",
        "privileges": "user (App Sandbox runner)",
        "evidence_role": "logs-only",
        "status": "partial",
    },
    {
        "id": "mac-policy-registration",
        "paths": ["book/evidence/experiments/mac-policy-registration"],
        "category": "tracing",
        "description": "MACF registration trace scaffolding and structure notes.",
        "privileges": "root, SIP disabled (if tracing)",
        "evidence_role": "tracing",
        "status": "design-only",
    },
]

EXTERNAL_ITEMS: List[Dict[str, Any]] = [
    {
        "id": "sb_validator",
        "title": "sb_validator (sandbox_check oracle)",
        "url": "https://github.com/Karmaz95/sb_validator",
        "category": "oracle",
        "relevance": "Reference for sandbox_check-based oracle lane; not host evidence.",
        "privileges": "user",
    },
    {
        "id": "sandbox_exec",
        "title": "sandbox exec(1)",
        "url": "https://man.freebsd.org/cgi/man.cgi?manpath=macOS+14.8&query=sandbox%2Dexec&sektion=1",
        "category": "policy-apply",
        "relevance": "Deprecated interface; context only for historical SBPL usage.",
        "privileges": "user",
    },
    {
        "id": "apple-sandbox-violations",
        "title": "Apple: Discovering and diagnosing App Sandbox violations",
        "url": "https://developer.apple.com/documentation/security/discovering-and-diagnosing-app-sandbox-violations",
        "category": "logging",
        "relevance": "Guidance for sandboxd reporting; contextual only.",
        "privileges": "user",
    },
    {
        "id": "oslogstore-limitations",
        "title": "OSLogStore on Monterey (system log access restrictions)",
        "url": "https://mjtsai.com/blog/2021/12/10/oslogstore-on-monterey/",
        "category": "logging",
        "relevance": "Confirms log access limits in sandboxed contexts; fingerprint only.",
        "privileges": "user",
    },
    {
        "id": "bdash-ops-filters",
        "title": "macOS sandbox action modifiers, filters, and operations",
        "url": "https://gist.github.com/bdash/ccbfb773ad57484532a74a982fe4f571",
        "category": "reference",
        "relevance": "Idea generator only; not a host-bound mapping.",
        "privileges": "n/a",
    },
    {
        "id": "apple-sandbox-guide",
        "title": "Apple Sandbox Guide v1.0",
        "url": "https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf",
        "category": "reference",
        "relevance": "Historical context; not authoritative for this host.",
        "privileges": "n/a",
    },
    {
        "id": "trace-directive-legacy",
        "title": "Quick 'n Dirty seatbelt/sandbox",
        "url": "https://gist.github.com/n8henrie/eaaa1a25753fadbd7715e85a38b99831",
        "category": "reference",
        "relevance": "Notes on legacy trace directive; treat as legacy only.",
        "privileges": "n/a",
    },
    {
        "id": "webkit-profile",
        "title": "WebKit com.apple.WebProcess.sb.in",
        "url": "https://github.com/WebKit/WebKit/blob/main/Source/WebKit/WebProcess/com.apple.WebProcess.sb.in",
        "category": "reference",
        "relevance": "Example of notification rules; not host evidence.",
        "privileges": "n/a",
    },
    {
        "id": "app-sandbox-exceptions",
        "title": "App Sandbox Temporary Exception Entitlements",
        "url": "https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html",
        "category": "entitlements",
        "relevance": "Explains mach-lookup exceptions; context only.",
        "privileges": "n/a",
    },
    {
        "id": "endpoint-security",
        "title": "EndpointSecurity event types",
        "url": "https://developer.apple.com/documentation/endpointsecurity/es_event_type_t",
        "category": "tracing",
        "relevance": "Privileged event channel; not part of baseline lane.",
        "privileges": "system extension / root",
    },
    {
        "id": "openbsm",
        "title": "OpenBSM auditing on macOS",
        "url": "https://derflounder.wordpress.com/2012/01/30/openbsm-auditing-on-mac-os-x/",
        "category": "tracing",
        "relevance": "Audit subsystem context; privileged configuration.",
        "privileges": "root",
    },
    {
        "id": "sandbox-extensions-mach",
        "title": "Sandbox extensions and mach tokens",
        "url": "https://mothersruin.com/software/Archaeology/reverse/bookmarks.html",
        "category": "mechanism",
        "relevance": "Non-file sandbox extensions; future mechanistic lane.",
        "privileges": "user",
    },
]


def _rg_available() -> bool:
    return subprocess.run(["/usr/bin/env", "rg", "--version"], capture_output=True).returncode == 0


def _rg_files(pattern: str, repo_root: Path) -> Iterable[Path]:
    cmd = [
        "rg",
        "-l",
        "-F",
        pattern,
        str(repo_root),
        "-g",
        "!.git/**",
        "-g",
        "!**/out/**",
        "-g",
        "!book/evidence/experiments/archive/**",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode not in (0, 1):
        return []
    files = []
    for line in res.stdout.splitlines():
        if line.strip():
            files.append(Path(line.strip()))
    return files


def collect_keyword_hits(repo_root: Path) -> Dict[str, List[str]]:
    """Scan the repo for keyword hits and return a map of path -> keywords."""
    hits: Dict[str, List[str]] = {}
    if not _rg_available():
        return hits
    for keyword in KEYWORDS:
        for path in _rg_files(keyword, repo_root):
            rel = path_utils.to_repo_relative(path, repo_root=repo_root)
            if any(rel.startswith(prefix) for prefix in EXCLUDED_SCAN_PREFIXES):
                continue
            hits.setdefault(rel, []).append(keyword)
    return hits


def assign_hits(items: List[Dict[str, Any]], hits: Dict[str, List[str]]) -> Dict[str, Any]:
    """Attach keyword hit paths to inventory items based on path prefixes."""
    by_prefix: Dict[str, Dict[str, Any]] = {}
    for item in items:
        for prefix in item.get("paths") or []:
            by_prefix[prefix] = item
    for item in items:
        item["files"] = []
    unclassified = []
    for path, keys in hits.items():
        match = None
        for prefix in sorted(by_prefix.keys(), key=lambda p: -len(p)):
            if path.startswith(prefix):
                match = by_prefix[prefix]
                break
        if match is None:
            unclassified.append({"path": path, "keywords": keys})
            continue
        match["files"].append({"path": path, "keywords": keys})
    return {"items": items, "unclassified": unclassified}


def load_world_id(baseline: Optional[Path] = None) -> str:
    """Load the baseline world_id from the world JSON file."""
    baseline_path = baseline or BASELINE
    if not baseline_path.exists():
        return "unknown"
    data = json.loads(baseline_path.read_text())
    return data.get("world_id") or data.get("id") or "unknown"


def build_runtime_inventory(*, repo_root: Optional[Path], out_path: Path) -> Dict[str, Any]:
    """Build and write the runtime tooling inventory document."""
    root = path_utils.ensure_absolute(repo_root or REPO_ROOT, REPO_ROOT)
    hits = collect_keyword_hits(root)
    assigned = assign_hits(IN_REPO_ITEMS, hits)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "world_id": load_world_id(),
        "generated_by": "book/api/runtime/analysis/inventory.py",
        "keywords": KEYWORDS,
        "in_repo": assigned["items"],
        "unclassified_hits": assigned["unclassified"],
        "external": EXTERNAL_ITEMS,
    }
    out_path = path_utils.ensure_absolute(out_path, root)
    out_path.write_text(json.dumps(payload, indent=2))
    return payload
