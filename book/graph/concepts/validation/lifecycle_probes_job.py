"""
Opt-in lifecycle probe runner.

This job is intentionally gated because it compiles and executes host-specific
probe binaries (Security.framework, libsandbox extension APIs).
"""

from __future__ import annotations

import os
from pathlib import Path

from book.api.lifecycle_probes import runner as probes
from book.api.path_utils import find_repo_root

from . import registry


REPO_ROOT = find_repo_root(Path(__file__))
ENV_ENABLE = "SANDBOX_LORE_RUN_LIFECYCLE_PROBES"

ENTITLEMENTS_OUT = "book/graph/concepts/validation/out/lifecycle/entitlements.json"
EXTENSIONS_OUT = "book/graph/concepts/validation/out/lifecycle/extensions_dynamic.md"


def _is_enabled() -> bool:
    raw = (os.environ.get(ENV_ENABLE) or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def run_lifecycle_probes_job():
    if not _is_enabled():
        return {
            "status": "skipped",
            "tier": "mapped",
            "notes": f"Set {ENV_ENABLE}=1 to build/run lifecycle probes on this host.",
            "inputs": [
                "book/api/lifecycle_probes/c/entitlements_example.c",
                "book/api/lifecycle_probes/c/extensions_demo.c",
            ],
            "outputs": [ENTITLEMENTS_OUT, EXTENSIONS_OUT],
        }

    ent_path = REPO_ROOT / ENTITLEMENTS_OUT
    ext_path = REPO_ROOT / EXTENSIONS_OUT

    ent = probes.capture_entitlements_evolution(ent_path, repo_root=REPO_ROOT, build=True)
    ext = probes.capture_extensions_dynamic(ext_path, repo_root=REPO_ROOT, build=True)

    ent_ok = ent.get("entitlements_present") is True
    ext_ok = ext.get("status") == "ok"

    status = "ok"
    if not ent_ok:
        status = "partial"
    if not ext_ok:
        status = "blocked"

    return {
        "status": status,
        "tier": "mapped",
        "inputs": [
            "book/api/lifecycle_probes/c/entitlements_example.c",
            "book/api/lifecycle_probes/c/extensions_demo.c",
        ],
        "outputs": [ENTITLEMENTS_OUT, EXTENSIONS_OUT],
        "notes": f"entitlements_present={ent.get('entitlements_present')}; extensions_status={ext.get('status')}; token_issued={ext.get('token_issued')}",
        "metrics": {
            "entitlements_present": bool(ent.get("entitlements_present") is True),
            "extensions_token_issued": bool(ext.get("token_issued") is True),
        },
    }


registry.register(
    registry.ValidationJob(
        id="lifecycle:probes",
        runner=run_lifecycle_probes_job,
        inputs=[
            "book/api/lifecycle_probes/c/entitlements_example.c",
            "book/api/lifecycle_probes/c/extensions_demo.c",
        ],
        outputs=[ENTITLEMENTS_OUT, EXTENSIONS_OUT],
        tags=["lifecycle", "lifecycle-extension"],
        description="(Opt-in) Build and run lifecycle probes; write validation/out/lifecycle/* outputs.",
        example_command=f"{ENV_ENABLE}=1 python -m book.graph.concepts.validation --id lifecycle:probes",
    )
)
