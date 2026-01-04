"""
Declarative map of validation tasks to inputs and expected artifacts.

Use this as the source of truth when wiring automation; keep scripts small and
confined to this directory. Fixtures live under book/evidence/syncretic/validation/fixtures.
"""

PLAN = {
    "static-format": [
        {
            "name": "modern-sb-sample",
            "example": "sbpl-corpus sample",
            "run": "python -m book.api.profile compile book/tools/sbpl/corpus/baseline/sample.sb --out book/evidence/syncretic/validation/fixtures/blobs/sample.sb.bin --no-preview",
            "artifacts": ["out/static/sb-sample.json"],
            "notes": "Compile sample.sb (modern graph format) and emit parsed header/op-table/node/regex/literal JSON via shared ingestion.",
        },
        {
            "name": "system-profiles-airlock-bsd",
            "example": "system SBPL templates",
            "run": "python -m book.api.profile compile /System/Library/Sandbox/Profiles/airlock.sb /System/Library/Sandbox/Profiles/bsd.sb --out-dir book/evidence/syncretic/validation/fixtures/blobs --no-preview",
            "artifacts": [
                "out/static/airlock.sb.bin.json",
                "out/static/bsd.sb.bin.json",
            ],
            "notes": "Compile system profiles (default airlock.sb, bsd.sb) with libsandbox; record profile format variant and OS/build in output.",
        },
        {
            "name": "sbpl-parameterization",
            "example": "parameterization validation jobs",
            "run": "python -m book.integration.carton validate --id structure:sbpl-parameterization --id structure:sbpl-param-value-matrix",
            "artifacts": [
                "out/sbpl_parameterization/status.json",
                "out/sbpl_param_value_matrix/status.json",
            ],
            "notes": "Compile minimal param-bearing SBPL specimens with/without params to capture parameterization behavior.",
        },
        {
            "name": "user-supplied-sbpl",
            "example": "custom SBPL input",
            "run": "python -m book.api.profile compile <input.sb> --out out/static/custom.sb.bin --no-preview",
            "artifacts": ["out/static/custom.sb.bin.json"],
            "notes": "Compile arbitrary SBPL, then parse via ingestion; captures parameterization/literal tables for bespoke cases.",
        },
        {
            "name": "legacy-decision-tree",
            "example": "legacy blob (optional)",
            "run": "python -m book.api.profile decode dump <legacy.sb.bin> --summary",
            "artifacts": [
                "out/static/legacy-header.json",
                "out/static/legacy-ops.json",
            ],
            "notes": "Decode a legacy decision-tree blob if one is available; record format variant and keep outputs clearly labeled.",
        },
    ],
    "semantic-graph": [
        {
            "name": "runtime-checks-normalization",
            "example": "runtime-checks experiment bundle",
            "run": "python -m book.api.runtime run --plan book/evidence/experiments/runtime-final-final/suites/runtime-checks/plan.json --channel launchd_clean --out book/evidence/experiments/runtime-final-final/suites/runtime-checks/out",
            "artifacts": ["out/experiments/runtime-checks/runtime_results.normalized.json"],
            "notes": "Plan-based probes (allow_all, metafilter_any, bucket4/5, sys:bsd) normalized via experiment:runtime-checks.",
        }
    ],
    "vocabulary-mapping": [
        {
            "name": "op-filter-tables-from-blobs",
            "example": "static-format blobs",
            "run": "ingestion applied to compiled blobs from static-format tasks",
            "artifacts": ["out/vocab/ops.json", "out/vocab/filters.json"],
            "notes": "Extract operation and filter vocab (name↔ID↔arg schema) from compiled blobs; key by OS/build and profile format variant.",
        },
        {
            "name": "runtime-cross-check",
            "example": "runtime-checks normalization",
            "run": "parse out/experiments/runtime-checks/runtime_results.normalized.json",
            "artifacts": ["out/vocab/runtime_usage.json"],
            "notes": "Map observed operation/filter names in probes to IDs from blob tables; flag unknown/mismatched entries for review.",
        },
    ],
    "lifecycle-extension": [
        {
            "name": "entitlements-diff",
            "example": "lifecycle entitlements probe",
            "run": "python -m book.api.lifecycle entitlements --out book/evidence/syncretic/validation/out/lifecycle/entitlements.json",
            "artifacts": ["out/lifecycle/entitlements.json"],
            "notes": "Capture signing identifier and entitlement sets for differently signed builds; correlate with filters in platform/app profiles.",
        },
        {
            "name": "platform-policy-probes",
            "example": "lifecycle platform probe",
            "run": "python -m book.api.lifecycle platform-policy --out book/evidence/syncretic/validation/out/lifecycle/platform.jsonl",
            "artifacts": ["out/lifecycle/platform.jsonl"],
            "notes": "Probe sysctl/SIP-protected paths/Mach services to show platform-layer denies; annotate SIP vs Seatbelt behavior and OS/build.",
        },
        {
            "name": "container-paths",
            "example": "lifecycle container probe",
            "run": "python -m book.api.lifecycle containers --out book/evidence/syncretic/validation/out/lifecycle/containers.json",
            "artifacts": ["out/lifecycle/containers.json"],
            "notes": "Record container roots/group containers/symlink targets; useful for tying path filters to real resolved paths.",
        },
        {
            "name": "extension-issuance",
            "example": "lifecycle extension probe",
            "run": "python -m book.api.lifecycle extensions --out book/evidence/syncretic/validation/out/lifecycle/extensions_dynamic.md",
            "artifacts": ["out/lifecycle/extensions_dynamic.md"],
            "notes": "Attempt to issue/consume/release extensions; log token issuance success/failure and any changed access. Note expected EPERM without entitlements.",
        },
        {
            "name": "sandbox-apply-attempt",
            "example": "lifecycle apply attempt",
            "run": "python -m book.api.lifecycle apply-attempt --out book/evidence/syncretic/validation/out/lifecycle/apply_attempt.json",
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
