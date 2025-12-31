from __future__ import annotations

import json
from pathlib import Path

from book.api import path_utils
from book.api.runtime.plans import builder as runtime_plan_builder
from book.api.runtime.plans import loader as runtime_plan
from book.api.runtime.plans import registry as runtime_registry


ROOT = path_utils.find_repo_root(Path(__file__))
EXPERIMENTS_ROOT = ROOT / "book" / "experiments"

RUN_SCRIPT_ALLOWLIST = {
    Path("book/experiments/bsd-airlock-highvals/run_probes.py"),
    Path("book/experiments/encoder-write-trace/run_trace.py"),
    Path("book/experiments/entitlement-diff/run_policywitness.py"),
    Path("book/experiments/entitlement-diff/run_probes.py"),
    Path("book/experiments/frida-testing/run_pw_frida.py"),
    Path("book/experiments/frida-testing/run_frida.py"),
    Path("book/experiments/libsandbox-encoder/run_network_matrix.py"),
    Path("book/experiments/libsandbox-encoder/run_phase_a.py"),
    Path("book/experiments/lifecycle-lockdown/run_lockdown.py"),
    Path("book/experiments/metadata-runner/run_metadata.py"),
}

PROHIBITED_TOPLEVEL = {
    "apply_preflight.json",
    "artifact_index.json",
    "baseline_results.json",
    "decode_tmp_profiles.json",
    "expected_matrix.generated.json",
    "expected_matrix.json",
    "launchctl",
    "mismatch_packets.jsonl",
    "mismatch_summary.json",
    "oracle_results.json",
    "path_witnesses.json",
    "run_manifest.json",
    "run_status.json",
    "runtime_events.normalized.json",
    "runtime_results.json",
    "summary.json",
    "summary.md",
}


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def _rel(path: Path) -> str:
    return str(path_utils.to_repo_relative(path, repo_root=ROOT))


def _experiment_roots_from_registry() -> list[Path]:
    index_doc = runtime_registry.load_registry_index()
    roots: list[Path] = []
    for entry in runtime_registry.iter_registry_paths(index_doc):
        roots.append(entry.probes.parent.parent)
    return roots


def _runtime_bundle_roots() -> list[Path]:
    roots = []
    for latest in EXPERIMENTS_ROOT.rglob("LATEST"):
        roots.append(latest.parent)
    return sorted(set(roots))


def _extract_how_to_run_sections(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    sections: list[str] = []
    i = 0
    while i < len(lines):
        if lines[i].strip().lower() == "## how to run":
            j = i + 1
            while j < len(lines) and not lines[j].startswith("## "):
                j += 1
            sections.append("\n".join(lines[i + 1 : j]).strip())
            i = j
            continue
        i += 1
    return sections


def test_plans_do_not_override_schema_versions():
    errors: list[str] = []
    for plan_path in runtime_plan.list_plan_paths(ROOT):
        doc = _load_json(plan_path)
        if "schema_versions" in doc:
            errors.append(f"{_rel(plan_path)} contains schema_versions")
    assert not errors, "plan schema overrides are not allowed:\n" + "\n".join(errors)


def test_registry_templates_cover_index():
    index_doc = runtime_registry.load_registry_index()
    template_ids = set(runtime_plan_builder.TEMPLATE_INDEX.keys())
    missing = []
    for entry in runtime_registry.iter_registry_paths(index_doc):
        if entry.registry_id not in template_ids:
            missing.append(entry.registry_id)
    assert not missing, "missing plan templates for registries:\n" + "\n".join(sorted(missing))


def test_template_materialization_matches_checked_in(tmp_path: Path):
    index_doc = runtime_registry.load_registry_index()
    errors: list[str] = []
    for entry in runtime_registry.iter_registry_paths(index_doc):
        template_id = entry.registry_id
        out_root = tmp_path / template_id
        result = runtime_plan_builder.build_plan_from_template(
            template_id,
            out_root,
            overwrite=True,
            write_expected_matrix=False,
        )
        plan_path = entry.probes.parent.parent / "plan.json"
        if not plan_path.exists():
            errors.append(f"{entry.registry_id} missing plan.json at {_rel(plan_path)}")
            continue
        pairs = [
            ("plan", plan_path, result.plan_path),
            ("probes", entry.probes, result.probes_path),
            ("profiles", entry.profiles, result.profiles_path),
        ]
        for label, actual_path, built_path in pairs:
            actual = _load_json(actual_path)
            built = _load_json(built_path)
            if actual != built:
                errors.append(f"{entry.registry_id} {label} drift: {_rel(actual_path)}")
    assert not errors, "template materialization drift:\n" + "\n".join(errors)


def test_experiment_run_script_allowlist():
    found = sorted(EXPERIMENTS_ROOT.rglob("run_*.py"))
    unexpected = []
    for path in found:
        rel = path.relative_to(ROOT)
        if rel not in RUN_SCRIPT_ALLOWLIST:
            unexpected.append(str(rel))
    assert not unexpected, "unexpected run_*.py scripts:\n" + "\n".join(unexpected)


def test_runtime_docs_have_single_how_to_run_block():
    errors: list[str] = []
    for root in _experiment_roots_from_registry():
        docs = [root / "README.md", root / "Report.md"]
        sections: list[tuple[Path, str]] = []
        for doc in docs:
            if not doc.exists():
                continue
            for section in _extract_how_to_run_sections(doc):
                sections.append((doc, section))
        if len(sections) != 1:
            found = ", ".join(_rel(doc) for doc, _ in sections) if sections else "none"
            errors.append(f"{_rel(root)} has {len(sections)} How to run blocks ({found})")
            continue
        doc, section = sections[0]
        if "python -m book.api.runtime run" not in section:
            errors.append(f"{_rel(doc)} How to run block missing runtime CLI invocation")
    assert not errors, "runtime doc guardrail failures:\n" + "\n".join(errors)


def test_runtime_bundle_roots_do_not_shadow_bundle_artifacts():
    errors: list[str] = []
    for root in _runtime_bundle_roots():
        for name in PROHIBITED_TOPLEVEL:
            path = root / name
            if path.exists():
                errors.append(f"{_rel(path)} should live under a run-scoped bundle")
    assert not errors, "top-level runtime artifacts found:\n" + "\n".join(errors)
