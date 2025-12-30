#@category Sandbox
"""
Find the field2/filter_arg reader helper (ldrb+ldrh, no masking) and its largest caller,
then dump their disassembly plus a small JSON summary.

Args: <out_dir> <build_id>
Outputs: book/dumps/ghidra/out/<build>/find-field2-evaluator/{field2_evaluator.json,helper.txt,eval.txt}

Assumptions/pitfalls:
- Requires functions/instructions recovered; avoid --no-analysis if you need reliable callers.
- Heuristics expect ARM64 mnemonics; ensure the KC was imported with the ARM64 language.

Notes:
- Heuristic ranking prefers small helpers with minimal masking/bitfield ops.
- Results are a starting point for manual review, not a proof of semantics.
"""

import json
import os


def iter_instructions(listing, func):
    return listing.getInstructions(func.getBody(), True)


def analyze_function(listing, func):
    stats = {"ldrb": 0, "ldrh": 0, "strh": 0, "mask": 0, "bitfield": 0}
    for instr in iter_instructions(listing, func):
        m = instr.getMnemonicString().lower()
        if m.startswith("ldrb"):
            stats["ldrb"] += 1
        elif m.startswith("ldrh"):
            stats["ldrh"] += 1
        elif m.startswith("strh"):
            stats["strh"] += 1
        elif (
            m.startswith("bfm")
            or m.startswith("bfi")
            or m.startswith("bfxil")
            or m.startswith("ubfm")
            or m.startswith("sbfm")
        ):
            stats["bitfield"] += 1
        elif m.startswith("and") or m.startswith("tst"):
            stats["mask"] += 1
    return stats


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
        stats = analyze_function(listing, func)
        if stats["ldrh"]:
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
                    "has_mask": stats["mask"] > 0,
                    "has_bitfield": stats["bitfield"] > 0,
                    "ldrb": stats["ldrb"],
                    "ldrh": stats["ldrh"],
                    "strh": stats["strh"],
                    "caller_count": len(caller_funcs),
                }
            )

    summary = {
        "build_id": build_id,
        "helper": None,
        "evaluator": None,
        "callers": [],
        "candidates": [],
        "candidate_count": 0,
        "function_count": len(funcs),
        "instruction_count": instr_count,
    }

    # Prefer mask-free, small helpers to approximate the field2 reader.
    candidates_sorted = sorted(candidates, key=lambda c: (c["has_mask"], c["size"]))
    for cand in candidates_sorted[:5]:
        summary["candidates"].append(
            {
                "name": cand["func"].getName(),
                "address": str(cand["func"].getEntryPoint()),
                "size": cand["size"],
                "has_mask": cand["has_mask"],
                "has_bitfield": cand.get("has_bitfield"),
                "ldrb": cand.get("ldrb"),
                "ldrh": cand.get("ldrh"),
                "strh": cand.get("strh"),
                "caller_count": cand["caller_count"],
            }
        )
    summary["candidate_count"] = len(candidates)

    helper = None
    # Prefer small, mask-free helpers with a single ldrh (and optional strh) and minimal bit fiddling.
    strict = sorted(
        [
            c
            for c in candidates
            if (not c["has_mask"])
            and (not c.get("has_bitfield"))
            and c.get("ldrh", 0) <= 2
            and c.get("strh", 0) <= 1
            and c["size"] <= 128
            and c["caller_count"] > 0
        ],
        key=lambda c: (-c["caller_count"], c.get("strh", 0) == 0, c["size"], c.get("ldrb", 0)),
    )
    if strict:
        helper = strict[0]["func"]
    else:
        widest = sorted(
            [
                c
                for c in candidates
                if (not c["has_mask"]) and (not c.get("has_bitfield")) and c["size"] <= 256
            ],
            key=lambda c: (-c["caller_count"], c["size"]),
        )
        if widest:
            helper = widest[0]["func"]
    if not helper and candidates_sorted:
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

    # Always try to dump _eval explicitly for comparison with the heuristic pick.
    eval_func = None
    for func in funcs:
        if func.getName() == "_eval":
            eval_func = func
            break
    if eval_func:
        eval_only_path = os.path.join(out_dir, "eval.txt")
        with open(eval_only_path, "w") as fh:
            fh.write("\n".join(dump_instructions(listing, eval_func)))
        summary["eval"] = {
            "name": eval_func.getName(),
            "address": str(eval_func.getEntryPoint()),
            "size": eval_func.getBody().getNumAddresses(),
            "dump": eval_only_path,
        }

    # Emit a full candidate list for manual triage.
    cand_dump = []
    for cand in sorted(candidates, key=lambda c: (c["has_mask"], c.get("has_bitfield"), c["size"])):
        cand_dump.append(
            {
                "name": cand["func"].getName(),
                "address": str(cand["func"].getEntryPoint()),
                "size": cand["size"],
                "has_mask": cand["has_mask"],
                "has_bitfield": cand.get("has_bitfield"),
                "ldrb": cand.get("ldrb"),
                "ldrh": cand.get("ldrh"),
                "strh": cand.get("strh"),
                "caller_count": cand["caller_count"],
            }
        )
    cand_path = os.path.join(out_dir, "candidates.json")
    with open(cand_path, "w") as fh:
        json.dump(cand_dump, fh, indent=2)
    summary["candidates_dump"] = cand_path

    out_path = os.path.join(out_dir, "field2_evaluator.json")
    with open(out_path, "w") as fh:
        json.dump(summary, fh, indent=2)
    print("[+] wrote %s" % out_path)


if __name__ == "__main__":
    run()
