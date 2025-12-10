import hashlib
import json
from pathlib import Path
import sys


def main() -> int:
    out_dir = Path(__file__).resolve().parent / "out"
    runs = sorted(out_dir.glob("*_run.json"))
    summary = {}
    ok = True
    for run_path in runs:
        with run_path.open() as f:
            run = json.load(f)
        blob_path = Path(run["blob"]["file"])
        data = blob_path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        expected_len = run["blob"]["len"]
        call_code_expected = 1 if run["handle_words"][0] != 0 else 0
        len_match = len(data) == expected_len
        call_code_match = call_code_expected == run["call_code"]
        summary[run_path.name] = {
            "blob_len": len(data),
            "expected_len": expected_len,
            "len_match": len_match,
            "sha256": sha,
            "call_code": run["call_code"],
            "call_code_expected": call_code_expected,
            "call_code_match": call_code_match,
        }
        ok = ok and len_match and call_code_match
    with (out_dir / "validation_summary.json").open("w") as f:
        json.dump(summary, f, indent=2)
    for name, info in summary.items():
        print(f"{name}: len={info['blob_len']} (expected {info['expected_len']}), "
              f"call_code={info['call_code']} (expected {info['call_code_expected']}), sha256={info['sha256']}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
