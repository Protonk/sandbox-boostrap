import hashlib
import json
from pathlib import Path
from typing import List, Dict, Any


WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"
EXPECTED_RUNS = {
    "init_params_probe": {
        "call_code": 0,
        "blob_len": 416,
        "blob_sha256": "19832eb9716a32459bee8398c8977fd1dfd575fa26606928f95728462a833c92",
    },
    "init_params_probe_container": {
        "call_code": 0,
        "blob_len": 416,
        "blob_sha256": "19832eb9716a32459bee8398c8977fd1dfd575fa26606928f95728462a833c92",
    },
}


def load_run(path: Path) -> Dict[str, Any]:
    with path.open() as f:
        return json.load(f)


def compute_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    out_dir = Path(__file__).resolve().parent / "out"
    repo_root = Path(__file__).resolve().parents[3]
    runs = sorted(out_dir.glob("*_run.json"))
    summary: Dict[str, Any] = {"world_id": WORLD_ID, "runs": []}
    ok = True

    for run_path in runs:
        run = load_run(run_path)
        blob_path = Path(run["blob"]["file"])
        blob_file = blob_path if blob_path.is_absolute() else repo_root / blob_path
        sha = compute_sha(blob_file)
        entry = {
            "run_id": run.get("run_id", run_path.stem),
            "world_id": run.get("world_id"),
            "call_code": run.get("call_code"),
            "blob_len": run["blob"]["len"],
            "blob_sha256": sha,
            "pointer_nonzero": run.get("pointer_nonzero", False),
            "forced_handle0": run.get("forced_handle0", False),
            "container_len": run.get("container_len", 0),
            "blob_file": str(blob_file),
        }
        expected = EXPECTED_RUNS.get(entry["run_id"])
        if entry["world_id"] != WORLD_ID:
            ok = False
            entry["error"] = f"world_id mismatch (got {entry['world_id']})"
        if expected:
            if entry["call_code"] != expected["call_code"]:
                ok = False
                entry["error_call_code"] = f"expected {expected['call_code']}"
            if entry["blob_len"] != expected["blob_len"]:
                ok = False
                entry["error_blob_len"] = f"expected {expected['blob_len']}"
            if entry["blob_sha256"] != expected["blob_sha256"]:
                ok = False
                entry["error_blob_sha256"] = f"expected {expected['blob_sha256']}"
        summary["runs"].append(entry)

    summary_path = out_dir / "validation_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))

    for entry in summary["runs"]:
        line = f"{entry['run_id']}: len={entry['blob_len']}, sha256={entry['blob_sha256']}, call_code={entry['call_code']}"
        if "error" in entry or "error_call_code" in entry or "error_blob_len" in entry or "error_blob_sha256" in entry:
            line += " [ERROR]"
        print(line)

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
