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


def has_out_files(out_dir: str):
    if not os.path.isdir(out_dir):
        return False
    for _ in list_files(out_dir):
        return True
    return False


def has_out_json(out_dir: str):
    if not os.path.isdir(out_dir):
        return False
    for path in list_files(out_dir):
        if path.endswith(".json"):
            return True
    return False


def experiment_names(root: str):
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if os.path.isdir(path):
            yield name


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))
    experiments_root = os.path.join(repo_root, "book", "experiments")
    tests_root = os.path.join(repo_root, "tests")
    outline_path = os.path.join(repo_root, "book", "Outline.md")
    chapters_root = os.path.join(repo_root, "book", "chapters")

    # Preload tests text for guardrail scans
    test_texts = []
    for path in list_files(tests_root):
        if path.endswith(".py"):
            test_texts.append(read_text(path))
    outline_text = read_text(outline_path)
    chapter_texts = []
    for path in list_files(chapters_root):
        if path.endswith(".md"):
            chapter_texts.append(read_text(path))

    experiments = []

    for name in experiment_names(experiments_root):
        exp_dir = os.path.join(experiments_root, name)
        plan_path = os.path.join(exp_dir, "Plan.md")
        notes_path = os.path.join(exp_dir, "Notes.md")
        report_path = os.path.join(exp_dir, "ResearchReport.md")
        out_dir = os.path.join(exp_dir, "out")

        plan_text = read_text(plan_path)
        notes_text = read_text(notes_path)
        report_text = read_text(report_path)

        has_plan = os.path.isfile(plan_path)
        has_notes = os.path.isfile(notes_path)
        has_report = os.path.isfile(report_path)

        # Data pass signals
        out_any = has_out_files(out_dir)
        out_json = has_out_json(out_dir)

        # Mapping references (heuristic: explicit path mention)
        mapping_refs = "book/graph/mappings" in plan_text or "book/graph/mappings" in report_text

        # Guardrail detection: any test mentioning experiment name or its out directory
        guardrail_present = False
        for t in test_texts:
            if name in t:
                guardrail_present = True
                break

        # Integration detection: outline/chapters mention the experiment name
        referenced_in_outline = name in outline_text
        referenced_in_chapters = any(name in ctext for ctext in chapter_texts)

        # Derive lifecycle flags and a coarse stage
        lifecycle_flags = {
            "scaffolded": has_plan and has_notes and has_report,
            "data_pass": out_any or out_json,
            "mapping_published": mapping_refs,
            "guardrailed": guardrail_present,
            "referenced": referenced_in_outline or referenced_in_chapters,
        }

        # Assign a coarse stage based on highest true flag in order
        stage_order = ["scaffolded", "data_pass", "mapping_published", "guardrailed", "referenced"]
        stage = "unscaffolded"
        for s in stage_order:
            if lifecycle_flags.get(s):
                stage = s
        experiments.append(
            {
                "name": name,
                "has_plan": has_plan,
                "has_notes": has_notes,
                "has_report": has_report,
                "has_out": out_any,
                "has_out_json": out_json,
                "mapping_refs": mapping_refs,
                "guardrail_present": guardrail_present,
                "referenced_in_outline": referenced_in_outline,
                "referenced_in_chapters": referenced_in_chapters,
                "lifecycle_flags": lifecycle_flags,
                "lifecycle_stage": stage,
            }
        )

    # Aggregate counts
    stage_counts = defaultdict(int)
    for exp in experiments:
        stage_counts[exp["lifecycle_stage"]] += 1

    payload = {
        "experiment_count": len(experiments),
        "stage_counts": dict(stage_counts),
        "experiments": experiments,
    }

    out_json_path = os.path.join(here, "lifecycle_audit.json")
    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)

    # Markdown summary
    lines = []
    lines.append("# Lifecycle and maturity audit")
    lines.append("")
    lines.append(f"- Experiments scanned: {payload['experiment_count']}")
    lines.append(f"- Stage counts: {payload['stage_counts']}")
    lines.append("")
    lines.append("## Per-experiment snapshot")
    for exp in experiments:
        lines.append(f"- {exp['name']}: stage={exp['lifecycle_stage']}, flags={exp['lifecycle_flags']}")
    out_md_path = os.path.join(here, "lifecycle_audit.md")
    with open(out_md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()

