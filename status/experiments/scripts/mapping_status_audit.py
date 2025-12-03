import json
import os
from collections import defaultdict


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def read_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def list_files(root: str):
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            if fn.endswith(".json"):
                yield os.path.join(dirpath, fn)


def load_mappings(mapping_root: str):
    mappings = {}
    for path in list_files(mapping_root):
        rel = os.path.relpath(path, mapping_root)
        data = read_json(path)
        if data is None:
            continue
        mappings[rel] = data
    return mappings


def summarize_mapping_status(data):
    top_status = None
    entry_status_counts = defaultdict(int)

    # top-level status may be at root or in metadata
    if isinstance(data, dict):
        if "status" in data and isinstance(data["status"], str):
            top_status = data["status"]
        elif "metadata" in data and isinstance(data["metadata"], dict):
            ms = data["metadata"].get("status")
            if isinstance(ms, str):
                top_status = ms

        # entries list
        entries = data.get("entries")
        if isinstance(entries, list):
            for e in entries:
                if isinstance(e, dict):
                    st = e.get("status")
                    if isinstance(st, str):
                        entry_status_counts[st] += 1

    return top_status, dict(entry_status_counts)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))
    experiments_root = os.path.join(repo_root, "book", "experiments")
    mappings_root = os.path.join(repo_root, "book", "graph", "mappings")

    # Load mapping JSONs
    mappings = load_mappings(mappings_root)
    mapping_statuses = {}
    for rel, data in mappings.items():
        top_status, entry_counts = summarize_mapping_status(data)
        mapping_statuses[rel] = {
            "top_status": top_status,
            "entry_status_counts": entry_counts,
        }

    # Load evidence_artifact_audit to associate experiments → mappings
    evidence_audit_path = os.path.join(here, "evidence_artifact_audit.json")
    evidence = read_json(evidence_audit_path) or {}
    experiments_info = {e["name"]: e for e in evidence.get("experiments", [])}

    experiments = []

    for name in sorted(os.listdir(experiments_root)):
        exp_dir = os.path.join(experiments_root, name)
        if not os.path.isdir(exp_dir):
            continue

        report_path = os.path.join(exp_dir, "ResearchReport.md")
        report_text = read_text(report_path)

        ev = experiments_info.get(name, {})
        produced = []
        consumed = []

        # Paths reported as outputs that live under book/graph/mappings/
        for out_rec in ev.get("outputs_reported", []):
            path = out_rec.get("path", "")
            if "book/graph/mappings/" in path:
                rel = path.split("book/graph/mappings/")[-1]
                if rel in mapping_statuses:
                    produced.append(
                        {
                            "path": rel,
                            **mapping_statuses[rel],
                        }
                    )

        # Inputs that are mappings
        for in_rec in ev.get("inputs", []):
            path = in_rec.get("path", "")
            if "book/graph/mappings/" in path:
                rel = path.split("book/graph/mappings/")[-1]
                if rel in mapping_statuses:
                    consumed.append(
                        {
                            "path": rel,
                            **mapping_statuses[rel],
                        }
                    )

        # Detect mentions of status words in report prose
        lower = report_text.lower()
        doc_status_mentions = []
        for status_word in ["status: ok", "status: partial", "status: blocked", "status: brittle"]:
            if status_word in lower:
                doc_status_mentions.append(status_word)

        experiments.append(
            {
                "name": name,
                "produced_mappings": produced,
                "consumed_mappings": consumed,
                "doc_status_mentions": doc_status_mentions,
            }
        )

    payload = {
        "experiment_count": len(experiments),
        "experiments": experiments,
    }

    out_json = os.path.join(here, "mapping_status_audit.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)

    # Markdown summary
    lines = []
    lines.append("# Mapping status audit")
    lines.append("")
    lines.append(f"- Experiments scanned: {payload['experiment_count']}")
    lines.append("")
    lines.append("## Experiments producing mappings")
    for exp in experiments:
        if exp["produced_mappings"]:
            paths = [m["path"] for m in exp["produced_mappings"]]
            lines.append(f"- {exp['name']}: {paths}")
    if len(lines) == 3:
        lines.append("- None")
    out_md = os.path.join(here, "mapping_status_audit.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()

