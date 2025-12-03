#@category Sandbox
"""
Find the field2/filter_arg reader helper (ldrb+ldrh, no masking) and its largest caller,
then dump their disassembly plus a small JSON summary.

Args: <out_dir> <build_id>
"""

import json
import os


def iter_instructions(listing, func):
    return listing.getInstructions(func.getBody(), True)


def analyze_function(listing, func):
    has_ldrb = False
    has_ldrh = False
    has_mask = False
    for instr in iter_instructions(listing, func):
        m = instr.getMnemonicString().lower()
        if m.startswith("ldrb"):
            has_ldrb = True
        elif m.startswith("ldrh"):
            has_ldrh = True
        elif m.startswith("and") or m.startswith("tst") or m.startswith("ubfx"):
            has_mask = True
    return has_ldrb, has_ldrh, has_mask


def dump_instructions(listing, func):
    lines = []
    for instr in iter_instructions(listing, func):
        lines.append("%s: %s" % (instr.getAddress(), instr))
    return lines


def run():
    args = getScriptArgs()
    if len(args) < 1:
        printerr("Usage: find_field2_evaluator.py <out_dir> [build_id]")
        return
    out_dir = args[0]
    build_id = args[1] if len(args) > 1 else ""
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    listing = currentProgram.getListing()

    instr_iter = listing.getInstructions(True)
    instr_count = 0
    for _ in instr_iter:
        instr_count += 1

    func_iter = listing.getFunctions(True)
    funcs = []
    while func_iter.hasNext():
        funcs.append(func_iter.next())

    candidates = []
    ref_mgr = currentProgram.getReferenceManager()
    func_mgr = currentProgram.getFunctionManager()

    for func in funcs:
        has_ldrb, has_ldrh, has_mask = analyze_function(listing, func)
        if has_ldrb and has_ldrh:
            size = func.getBody().getNumAddresses()
            caller_funcs = set()
            for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
                caller = func_mgr.getFunctionContaining(ref.getFromAddress())
                if caller:
                    caller_funcs.add(caller)
            candidates.append(
                {
                    "func": func,
                    "size": size,
                    "has_mask": has_mask,
                    "caller_count": len(caller_funcs),
                }
            )

    summary = {
        "build_id": build_id,
        "helper": None,
        "evaluator": None,
        "callers": [],
        "candidates": [],
        "function_count": len(funcs),
        "instruction_count": instr_count,
    }

    candidates_sorted = sorted(candidates, key=lambda c: (c["has_mask"], c["size"]))
    for cand in candidates_sorted[:5]:
        summary["candidates"].append(
            {
                "name": cand["func"].getName(),
                "address": str(cand["func"].getEntryPoint()),
                "size": cand["size"],
                "has_mask": cand["has_mask"],
                "caller_count": cand["caller_count"],
            }
        )

    helper = None
    # Prefer widely-used small helpers with no masking.
    widest = sorted(
        [c for c in candidates if not c["has_mask"] and c["size"] <= 256],
        key=lambda c: (-c["caller_count"], c["size"]),
    )
    if widest:
        helper = widest[0]["func"]
    elif candidates_sorted:
        helper = candidates_sorted[0]["func"]  # fallback to smallest candidate

    if helper:
        helper_path = os.path.join(out_dir, "helper.txt")
        with open(helper_path, "w") as fh:
            fh.write("\n".join(dump_instructions(listing, helper)))
        summary["helper"] = {
            "name": helper.getName(),
            "address": str(helper.getEntryPoint()),
            "size": helper.getBody().getNumAddresses(),
            "dump": helper_path,
        }

        # Collect callers
        func_mgr = currentProgram.getFunctionManager()
        seen = {}
        for ref in currentProgram.getReferenceManager().getReferencesTo(helper.getEntryPoint()):
            caller = func_mgr.getFunctionContaining(ref.getFromAddress())
            if caller:
                seen[caller] = caller.getBody().getNumAddresses()
        callers = sorted(seen.items(), key=lambda kv: -kv[1])
        summary["callers"] = [
            {"name": f.getName(), "address": str(f.getEntryPoint()), "size": sz}
            for f, sz in callers
        ]

        if callers:
            best = callers[0][0]
            eval_path = os.path.join(out_dir, "evaluator.txt")
            with open(eval_path, "w") as fh:
                fh.write("\n".join(dump_instructions(listing, best)))
            summary["evaluator"] = {
                "name": best.getName(),
                "address": str(best.getEntryPoint()),
                "size": best.getBody().getNumAddresses(),
                "dump": eval_path,
            }

    out_path = os.path.join(out_dir, "field2_evaluator.json")
    with open(out_path, "w") as fh:
        json.dump(summary, fh, indent=2)
    print("[+] wrote %s" % out_path)


if __name__ == "__main__":
    run()
