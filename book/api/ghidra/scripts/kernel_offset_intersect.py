#@category Sandbox
"""
Intersect multiple offset scan outputs by function.
Args: <out_dir> <build_id> <scan_json> [scan_json ...] [limit=N]

Outputs: <out_dir>/offset_intersect.json
"""

import json
import os
import sys
import traceback


_RUN_CALLED = False


def _ensure_out_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _parse_args(argv):
    out_dir = None
    build_id = None
    scans = []
    limit = 5
    for token in argv:
        if token.startswith("limit="):
            try:
                limit = int(token.split("=", 1)[1], 10)
            except Exception:
                pass
            continue
        if out_dir is None:
            out_dir = token
            continue
        if build_id is None:
            build_id = token
            continue
        scans.append(token)
    return out_dir, build_id, scans, limit


def _load_scan(path):
    with open(path, "r") as f:
        data = json.load(f)
    hits = data.get("hits", [])
    meta = data.get("meta", {})
    by_func = {}
    for hit in hits:
        func = hit.get("function")
        if not func:
            continue
        by_func.setdefault(func, []).append(
            {
                "address": hit.get("address"),
                "mnemonic": hit.get("mnemonic"),
                "inst": hit.get("inst"),
            }
        )
    return {
        "path": path,
        "meta": meta,
        "by_func": by_func,
    }


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        if "getScriptArgs" in globals():
            argv = list(getScriptArgs())
        else:
            argv = sys.argv[1:]
        out_dir, build_id, scans, limit = _parse_args(argv)
        if not out_dir or not build_id or not scans:
            print("usage: kernel_offset_intersect.py <out_dir> <build_id> <scan_json> [scan_json ...] [limit=N]")
            return

        _ensure_out_dir(out_dir)
        scans_data = [_load_scan(p) for p in scans]
        func_sets = [set(s["by_func"].keys()) for s in scans_data]
        if not func_sets:
            intersection = set()
        else:
            intersection = set(func_sets[0])
            for s in func_sets[1:]:
                intersection &= s

        intersection_entries = []
        for func in sorted(intersection):
            entry = {"function": func, "hits": {}}
            for scan in scans_data:
                hits = scan["by_func"].get(func, [])
                entry["hits"][scan["path"]] = hits[:limit]
            intersection_entries.append(entry)

        out = {
            "build_id": build_id,
            "scan_paths": scans,
            "limit": limit,
            "intersection_count": len(intersection_entries),
            "intersection": intersection_entries,
        }
        with open(os.path.join(out_dir, "offset_intersect.json"), "w") as f:
            json.dump(out, f, indent=2, sort_keys=True)
        print("kernel_offset_intersect: wrote %d entries" % len(intersection_entries))
    except Exception:
        if out_dir:
            try:
                _ensure_out_dir(out_dir)
                with open(os.path.join(out_dir, "error.log"), "w") as err:
                    traceback.print_exc(file=err)
            except Exception:
                pass
        traceback.print_exc()


run()
