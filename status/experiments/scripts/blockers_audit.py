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


def experiment_dirs(experiments_root: str):
    for name in sorted(os.listdir(experiments_root)):
        path = os.path.join(experiments_root, name)
        if os.path.isdir(path):
            yield name, path


BLOCKER_PATTERNS = [
    (r"\bEPERM\b", "runtime_apply_gate"),
    (r"\bsandbox_(init|apply)\b", "runtime_apply_gate"),
    (r"\bEACCES\b", "runtime_apply_gate"),
    (r"node_count=0", "decoder_limit"),
    (r"\bno callers\b", "kernel_or_ghidra_limit"),
    (r"\bno references\b", "kernel_or_ghidra_limit"),
    (r"\bblocked\b", "generic_blocker"),
    (r"\bcurrent blocker\b", "generic_blocker"),
    (r"\broadblock\b", "generic_blocker"),
    (r"\bcrash\b", "generic_blocker"),
    (r"\bpanic\b", "generic_blocker"),
    (r"Ghidra", "kernel_or_ghidra_limit"),
    (r"sandbox-exec", "tooling_gap"),
]


def find_blockers(text: str):
    blockers = []
    lines = text.splitlines()
    joined = "\n".join(lines)
    for pat, kind in BLOCKER_PATTERNS:
        for m in re.finditer(pat, joined, flags=re.IGNORECASE):
            # capture a small context window around the match
            start = max(0, m.start() - 80)
            end = min(len(joined), m.end() + 80)
            snippet = joined[start:end].replace("\n", " ")
            blockers.append({"type": kind, "pattern": pat, "snippet": snippet})
    return blockers


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))
    experiments_root = os.path.join(repo_root, "book", "experiments")

    experiments = []
    type_counts = defaultdict(int)

    for name, exp_dir in experiment_dirs(experiments_root):
        notes_text = read_text(os.path.join(exp_dir, "Notes.md"))
        report_text = read_text(os.path.join(exp_dir, "ResearchReport.md"))
        combined = notes_text + "\n" + report_text
        blockers = find_blockers(combined)
        for b in blockers:
            type_counts[b["type"]] += 1

        experiments.append(
            {
                "name": name,
                "has_blockers": bool(blockers),
                "blockers": blockers,
            }
        )

    payload = {
        "experiment_count": len(experiments),
        "blocker_type_counts": dict(sorted(type_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "experiments": experiments,
    }

    out_json = os.path.join(here, "blockers_audit.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)

    # Markdown summary
    lines = []
    lines.append("# Blockers and failure-modes audit")
    lines.append("")
    lines.append(f"- Experiments scanned: {payload['experiment_count']}")
    lines.append(f"- Blocker type counts: {payload['blocker_type_counts']}")
    lines.append("")
    lines.append("## Experiments with recorded blockers")
    for exp in experiments:
        if exp["has_blockers"]:
            kinds = sorted({b["type"] for b in exp["blockers"]})
            lines.append(f"- {exp['name']}: {kinds}")
    if len(lines) == 3:
        lines.append("- None")
    out_md = os.path.join(here, "blockers_audit.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()

