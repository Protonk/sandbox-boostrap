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


def extract_shell_commands(text: str):
    commands = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("```"):
            # skip fence markers
            continue
        # Heuristic: lines that look like shell commands
        if stripped.startswith("$"):
            commands.append(stripped.lstrip("$").strip())
        elif stripped.startswith("./") or stripped.startswith("python ") or stripped.startswith("pytest "):
            commands.append(stripped)
        elif stripped.startswith("bash ") or stripped.startswith("swiftc ") or stripped.startswith("clang "):
            commands.append(stripped)
    return commands


def detect_run_phrases(text: str):
    lower = text.lower()
    phrases = ["how to run", "run this", "to run", "usage:"]
    return any(p in lower for p in phrases)


def detect_external_deps(text: str):
    lower = text.lower()
    deps = set()
    if "ghidra" in lower:
        deps.add("ghidra")
    if "codesign" in lower:
        deps.add("codesign")
    if "sandbox-exec" in lower:
        deps.add("sandbox-exec")
    if "swiftc" in lower:
        deps.add("swiftc")
    if "dsc_extractor" in lower:
        deps.add("dsc_extractor")
    if "sbpl-wrapper" in lower or "sbpl wrapper" in lower or "wrapper --sbpl" in lower:
        deps.add("sbpl-wrapper")
    if "file_probe" in lower:
        deps.add("file_probe")
    return sorted(deps)


def has_entry_scripts(exp_dir: str):
    has_any = False
    scripts = []
    for path in list_files(exp_dir):
        base = os.path.basename(path)
        if base.endswith(".py") or base.endswith(".sh"):
            # Skip cached bytecode
            if "__pycache__" in path:
                continue
            has_any = True
            scripts.append(os.path.relpath(path, exp_dir))
    return has_any, sorted(scripts)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))
    experiments_root = os.path.join(repo_root, "book", "experiments")

    records = []

    for name, exp_dir in experiment_dirs(experiments_root):
        plan_text = read_text(os.path.join(exp_dir, "Plan.md"))
        report_text = read_text(os.path.join(exp_dir, "ResearchReport.md"))
        combined = plan_text + "\n" + report_text

        commands = extract_shell_commands(combined)
        doc_run_instructions = bool(commands) or detect_run_phrases(combined)
        external_deps = detect_external_deps(combined)
        has_scripts, scripts = has_entry_scripts(exp_dir)

        records.append(
            {
                "name": name,
                "doc_run_instructions": doc_run_instructions,
                "shell_commands": commands,
                "has_entry_scripts": has_scripts,
                "entry_scripts": scripts,
                "external_deps": external_deps,
            }
        )

    summary = {
        "experiment_count": len(records),
        "experiments": records,
    }

    out_json = os.path.join(here, "repro_audit.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)

    # Markdown summary
    lines = []
    lines.append("# Reproducibility and rerunability audit")
    lines.append("")
    lines.append(f"- Experiments scanned: {summary['experiment_count']}")
    lines.append("")
    lines.append("## Per-experiment reproducibility snapshot")
    for rec in records:
        lines.append(
            f"- {rec['name']}: doc_run_instructions={rec['doc_run_instructions']}, "
            f"has_entry_scripts={rec['has_entry_scripts']}, external_deps={rec['external_deps']}"
        )
    out_md = os.path.join(here, "repro_audit.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()

