"""
Declarative map of validation tasks to examples and expected artifacts.

Use this as the source of truth when wiring automation; keep scripts small and
confined to this directory. Example code lives under book/examples/.
"""

PLAN = {
    "static-format": [
        {
            "name": "modern-sb-sample",
            "example": "sb",
            "run": "python -m book.api.profile compile book/examples/sb/sample.sb --out book/graph/concepts/validation/fixtures/blobs/sample.sb.bin --no-preview",
            "artifacts": ["out/static/sb-sample.json"],
            "notes": "Compile sample.sb (modern graph format) and emit parsed header/op-table/node/regex/literal JSON via shared ingestion.",
        },
        {
            "name": "system-profiles-airlock-bsd",
            "example": "extract_sbs",
            "run": "python -m book.api.profile compile /System/Library/Sandbox/Profiles/airlock.sb /System/Library/Sandbox/Profiles/bsd.sb --out-dir book/graph/concepts/validation/fixtures/blobs --no-preview",
            "artifacts": [
                "out/static/airlock.sb.bin.json",
                "out/static/bsd.sb.bin.json",
            ],
            "notes": "Compile system profiles (default airlock.sb, bsd.sb) with libsandbox; record profile format variant and OS/build in output.",
        },
        {
            "name": "user-supplied-sbpl",
            "example": "sbsnarf",
            "run": "python -m book.api.profile compile <input.sb> --out out/static/custom.sb.bin --no-preview",
            "artifacts": ["out/static/custom.sb.bin.json"],
            "notes": "Compile arbitrary SBPL, then parse via ingestion; captures parameterization/literal tables for bespoke cases.",
        },
        {
            "name": "legacy-decision-tree",
            "example": "sbdis + resnarf",
            "run": "book/examples/sbdis/run-demo.sh <legacy.sb.bin>",
            "artifacts": [
                "out/static/legacy-header.json",
                "out/static/legacy-ops.json",
                "out/static/legacy-regex/*.re",
            ],
            "notes": "Parse early decision-tree format; resnarf extracts regex blobs; document format variant for mapping.",
        },
    ],
    "semantic-graph": [
        {
            "name": "metafilter-boolean-shapes",
            "example": "metafilter-tests",
            "run": "book/examples/metafilter-tests/metafilter_demo.sh",
            "artifacts": ["out/semantic/metafilter.jsonl"],
            "notes": "Run tiny SBPL profiles with require-any/all/not; capture attempted paths, allow/deny, and graph path ids; annotate if TCC/SIP interferes.",
        },
        {
            "name": "sbpl-params-variants",
            "example": "sbpl-params",
            "run": "book/examples/sbpl-params/params_demo.sh",
            "artifacts": ["out/semantic/params.jsonl"],
            "notes": "Compile/run parameterized profiles with/without -D params; record path outcomes and compiled literals to show parameter substitution.",
        },
        {
            "name": "network-filter-probes",
            "example": "network-filters",
            "run": "book/examples/network-filters/network_demo.c",
            "artifacts": ["out/semantic/network.jsonl"],
            "notes": "Exercise TCP/UDP/UNIX sockets under selected profiles; log socket domain/type/addr plus allow/deny. Note: distinguish sandbox denial from ECONNREFUSED.",
        },
        {
            "name": "mach-lookup-filters",
            "example": "mach-services",
            "run": "book/examples/mach-services (server/client)",
            "artifacts": ["out/semantic/mach.jsonl"],
            "notes": "Register and lookup services; capture which names succeed/fail under target profiles. Separate policy denials from missing-service errors.",
        },
    ],
    "vocabulary-mapping": [
        {
            "name": "op-filter-tables-from-blobs",
            "example": "sb + extract_sbs",
            "run": "ingestion applied to compiled blobs from static-format tasks",
            "artifacts": ["out/vocab/ops.json", "out/vocab/filters.json"],
            "notes": "Extract operation and filter vocab (name↔ID↔arg schema) from compiled blobs; key by OS/build and profile format variant.",
        },
        {
            "name": "runtime-cross-check",
            "example": "semantic probes",
            "run": "parse out/semantic/*.jsonl",
            "artifacts": ["out/vocab/runtime_usage.json"],
            "notes": "Map observed operation/filter names in probes to IDs from blob tables; flag unknown/mismatched entries for review.",
        },
    ],
    "lifecycle-extension": [
        {
            "name": "entitlements-diff",
            "example": "entitlements-evolution",
            "run": "python -m book.api.lifecycle entitlements --out book/graph/concepts/validation/out/lifecycle/entitlements.json",
            "artifacts": ["out/lifecycle/entitlements.json"],
            "notes": "Capture signing identifier and entitlement sets for differently signed builds; correlate with filters in platform/app profiles.",
        },
        {
            "name": "platform-policy-probes",
            "example": "platform-policy-checks",
            "run": "python -m book.api.lifecycle platform-policy --out book/graph/concepts/validation/out/lifecycle/platform.jsonl",
            "artifacts": ["out/lifecycle/platform.jsonl"],
            "notes": "Probe sysctl/SIP-protected paths/Mach services to show platform-layer denies; annotate SIP vs Seatbelt behavior and OS/build.",
        },
        {
            "name": "container-paths",
            "example": "containers-and-redirects",
            "run": "python -m book.api.lifecycle containers --out book/graph/concepts/validation/out/lifecycle/containers.json",
            "artifacts": ["out/lifecycle/containers.json"],
            "notes": "Record container roots/group containers/symlink targets; useful for tying path filters to real resolved paths.",
        },
        {
            "name": "extension-issuance",
            "example": "extensions-dynamic",
            "run": "python -m book.api.lifecycle extensions --out book/graph/concepts/validation/out/lifecycle/extensions_dynamic.md",
            "artifacts": ["out/lifecycle/extensions_dynamic.md"],
            "notes": "Attempt to issue/consume/release extensions; log token issuance success/failure and any changed access. Note expected EPERM without entitlements.",
        },
        {
            "name": "sandbox-apply-attempt",
            "example": "libsandcall",
            "run": "python -m book.api.lifecycle apply-attempt --out book/graph/concepts/validation/out/lifecycle/apply_attempt.json",
            "artifacts": ["out/lifecycle/apply_attempt.json"],
            "notes": "Demonstrate compilation succeeds but apply fails without entitlements/SIP relaxation; captures lifecycle stage where policy attachment is refused.",
        },
    ],
}


def list_tasks():
    """Print a concise list of tasks per cluster."""
    for cluster, tasks in PLAN.items():
        print(f"[{cluster}]")
        for task in tasks:
            print(f"  - {task['name']}: {task['example']} -> {task['artifacts']}")


if __name__ == "__main__":
    list_tasks()
