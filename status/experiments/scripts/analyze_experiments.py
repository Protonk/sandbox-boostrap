import json
import os
import re
from collections import Counter, defaultdict


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def extract_headings(text: str):
    headings = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            # strip leading '#' and whitespace
            h = line.lstrip().lstrip("#").strip()
            if h:
                headings.append(h)
    return headings


def extract_deliverables_lines(plan_text: str):
    lines = plan_text.splitlines()
    deliverables_blocks = []
    in_block = False
    current_block = []

    for line in lines:
        stripped = line.strip()
        # Start of a deliverables section
        if stripped.lower().startswith("deliverables"):
            # flush existing
            if current_block:
                deliverables_blocks.append(current_block)
                current_block = []
            in_block = True
            # we keep the line itself too
            current_block.append(line)
            continue

        if in_block:
            # stop on blank line or a new top-level heading
            if stripped == "" or stripped.startswith("#"):
                in_block = False
                if current_block:
                    deliverables_blocks.append(current_block)
                    current_block = []
                continue
            current_block.append(line)

    if current_block:
        deliverables_blocks.append(current_block)

    # flatten blocks into a single list of non-empty, non-heading lines
    flat = []
    for block in deliverables_blocks:
        for line in block:
            if line.strip() and not line.lstrip().startswith("#"):
                flat.append(line.rstrip())
    return flat


def classify_baseline(report_text: str):
    """
    Classify how well the host baseline is recorded in a ResearchReport.
    Heuristic: look for macOS version/build, SIP, and host markers.
    """
    text = report_text
    lower = text.lower()

    if not text.strip():
        return {"status": "missing", "markers": []}

    markers = []

    patterns = [
        r"macos\s+14\.4\.1",
        r"\b23e224\b",
        r"sip enabled",
        r"apple silicon",
        r"host:",
    ]
    for pat in patterns:
        if re.search(pat, lower):
            markers.append(pat)

    # Explicit TBD markers
    if "host: tbd" in lower or "host: tdb" in lower:
        if markers:
            status = "partial"
        else:
            status = "missing"
        markers.append("host:tbd/tdb")
        return {"status": status, "markers": markers}

    if len(markers) >= 2:
        status = "recorded"
    elif len(markers) == 1:
        status = "partial"
    else:
        status = "missing"

    return {"status": status, "markers": markers}


def classify_deliverable_line(line: str):
    """Roughly categorize a deliverable line by keywords."""
    lower = line.lower()
    kinds = set()
    if "book/graph/mappings" in lower or "graph/mappings" in lower:
        kinds.add("mapping")
    if "out/" in lower or "json" in lower:
        kinds.add("out-json")
    if "guardrail" in lower or "tests/" in lower or "pytest" in lower:
        kinds.add("guardrail")
    if "runtime" in lower:
        kinds.add("runtime")
    if "ghidra" in lower or "kernel" in lower:
        kinds.add("kernel-facing")
    if "sbpl" in lower or ".sb" in lower:
        kinds.add("sbpl/profile")
    if "wrapper" in lower or "file_probe" in lower or "sandbox_runner" in lower:
        kinds.add("harness")
    return sorted(kinds)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))
    experiments_root = os.path.join(repo_root, "book", "experiments")

    experiments = []

    for name in sorted(os.listdir(experiments_root)):
        exp_dir = os.path.join(experiments_root, name)
        if not os.path.isdir(exp_dir):
            continue

        plan_path = os.path.join(exp_dir, "Plan.md")
        report_path = os.path.join(exp_dir, "ResearchReport.md")

        plan_text = read_text(plan_path)
        report_text = read_text(report_path)

        plan_headings = extract_headings(plan_text)
        report_headings = extract_headings(report_text)

        deliverables_lines = extract_deliverables_lines(plan_text)
        has_deliverables = bool(deliverables_lines)

        baseline_info = classify_baseline(report_text)

        deliverables_kinds = []
        for line in deliverables_lines:
            kinds = classify_deliverable_line(line)
            if kinds:
                deliverables_kinds.extend(kinds)

        experiments.append(
            {
                "name": name,
                "plan_headings": plan_headings,
                "report_headings": report_headings,
                "has_deliverables": has_deliverables,
                "deliverables_lines": deliverables_lines,
                "deliverables_kinds": sorted(set(deliverables_kinds)),
                "baseline": baseline_info,
            }
        )

    # Aggregate statistics
    plan_heading_counts = Counter()
    report_heading_counts = Counter()
    baseline_status_counts = Counter()
    deliverables_kind_counts = Counter()

    for exp in experiments:
        for h in exp["plan_headings"]:
            plan_heading_counts[h] += 1
        for h in exp["report_headings"]:
            report_heading_counts[h] += 1
        baseline_status_counts[exp["baseline"]["status"]] += 1
        for k in exp["deliverables_kinds"]:
            deliverables_kind_counts[k] += 1

    summary = {
        "experiment_count": len(experiments),
        "plan_heading_counts": plan_heading_counts,
        "report_heading_counts": report_heading_counts,
        "baseline_status_counts": baseline_status_counts,
        "deliverables_kind_counts": deliverables_kind_counts,
    }

    # Convert Counters to plain dicts for JSON
    def counter_to_dict(c: Counter):
        return {k: int(v) for k, v in sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))}

    json_payload = {
        "experiments": experiments,
        "summary": {
            "experiment_count": summary["experiment_count"],
            "plan_heading_counts": counter_to_dict(summary["plan_heading_counts"]),
            "report_heading_counts": counter_to_dict(summary["report_heading_counts"]),
            "baseline_status_counts": counter_to_dict(summary["baseline_status_counts"]),
            "deliverables_kind_counts": counter_to_dict(summary["deliverables_kind_counts"]),
        },
    }

    out_json_path = os.path.join(here, "scaffold_census.json")
    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(json_payload, f, indent=2, sort_keys=True)

    # Also emit a human-oriented markdown summary
    lines = []
    lines.append("# Experiment scaffold census")
    lines.append("")
    lines.append(f"- Experiments scanned: {json_payload['summary']['experiment_count']}")
    lines.append(
        f"- Baseline status counts: {json_payload['summary']['baseline_status_counts']}"
    )
    lines.append(
        f"- Deliverable kind counts: {json_payload['summary']['deliverables_kind_counts']}"
    )
    lines.append("")
    lines.append("## Common Plan.md headings")
    for h, count in json_payload["summary"]["plan_heading_counts"].items():
        lines.append(f"- {h} — {count}")
    lines.append("")
    lines.append("## Common ResearchReport.md headings")
    for h, count in json_payload["summary"]["report_heading_counts"].items():
        lines.append(f"- {h} — {count}")

    out_md_path = os.path.join(here, "scaffold_census.md")
    with open(out_md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()

