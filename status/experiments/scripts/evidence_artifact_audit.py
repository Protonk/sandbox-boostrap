import json
import os
import re
from collections import defaultdict


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def list_files(root: str):
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def experiment_dirs(experiments_root: str):
    for name in sorted(os.listdir(experiments_root)):
        path = os.path.join(experiments_root, name)
        if os.path.isdir(path):
            yield name, path


def classify_path(path: str):
    if "book/examples/" in path:
        return "compiled_profile_or_example"
    if "book/graph/mappings/" in path:
        return "mapping"
    if "dumps/" in path:
        return "dump_or_kernel"
    if "dyld" in path or "dsc" in path:
        return "dyld_or_shared_cache"
    if "/out/" in path:
        return "experiment_out"
    if "runtime_profiles" in path:
        return "runtime_profile"
    return "other"


def extract_backticked_paths(text: str):
    # crude: find `...` spans
    paths = []
    for match in re.finditer(r"`([^`]+)`", text):
        val = match.group(1)
        if "/" in val:
            paths.append(val)
    return paths


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))
    experiments_root = os.path.join(repo_root, "book", "experiments")

    records = []

    for name, exp_dir in experiment_dirs(experiments_root):
        report_path = os.path.join(exp_dir, "ResearchReport.md")
        report_text = read_text(report_path)

        backticked_paths = extract_backticked_paths(report_text)
        input_paths = []
        output_paths_reported = []

        for p in backticked_paths:
            # rough heuristic: treat 'out/' and 'book/graph/mappings' as outputs, others as inputs
            if "/out/" in p or "book/graph/mappings/" in p:
                output_paths_reported.append(p)
            else:
                input_paths.append(p)

        # Also find actual out/* files on disk and see if they are mentioned
        out_dir = os.path.join(exp_dir, "out")
        outputs_fs = []
        outputs_unmentioned = []
        if os.path.isdir(out_dir):
            for path in list_files(out_dir):
                rel = os.path.relpath(path, repo_root)
                outputs_fs.append(rel)
                base = os.path.basename(path)
                if base not in report_text:
                    outputs_unmentioned.append(rel)

        inputs_structured = [
            {"path": p, "kind": classify_path(p)} for p in sorted(set(input_paths))
        ]
        outputs_reported_structured = [
            {"path": p, "kind": classify_path(p)}
            for p in sorted(set(output_paths_reported))
        ]

        records.append(
            {
                "name": name,
                "inputs": inputs_structured,
                "outputs_reported": outputs_reported_structured,
                "outputs_fs": sorted(outputs_fs),
                "outputs_unmentioned": sorted(outputs_unmentioned),
            }
        )

    summary = {
        "experiment_count": len(records),
        "experiments": records,
    }

    out_json = os.path.join(here, "evidence_artifact_audit.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)

    # Markdown summary
    lines = []
    lines.append("# Evidence and artifact audit")
    lines.append("")
    lines.append(f"- Experiments scanned: {summary['experiment_count']}")
    lines.append("")
    lines.append("## Experiments with unmentioned out/ artifacts")
    for rec in records:
        if rec["outputs_unmentioned"]:
            lines.append(f"- {rec['name']}: unmentioned={rec['outputs_unmentioned']}")
    if len(lines) == 3:
        lines.append("- None")
    out_md = os.path.join(here, "evidence_artifact_audit.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()

