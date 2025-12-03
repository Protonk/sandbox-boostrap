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


def looks_like_reader(listing, func):
    # Heuristic: small helper containing ldrb+ldrh and no masking/bit-tests.
    body_size = func.getBody().getNumAddresses()
    if body_size > 128:
        return False
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
    return has_ldrb and has_ldrh and not has_mask


def dump_instructions(listing, func):
    lines = []
    for instr in iter_instructions(listing, func):
        lines.append(f"{instr.getAddress()}: {instr}")
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

    helper = None
    for func in listing.getFunctions(True):
        if looks_like_reader(listing, func):
            helper = func
            break

    summary = {"build_id": build_id, "helper": None, "evaluator": None, "callers": []}

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
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    run()
