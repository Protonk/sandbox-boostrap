#@category Sandbox
"""
Node-struct scanner focused on the sandbox kext:

Mode:
  scan <out_dir> [eval_fn_or_addr]

Does three things:
  1) Builds the set of functions reachable from `_eval` (default addr fffffe000b40d698).
  2) Inside that reachable set, looks for functions that appear to index into a
     fixed-stride array of small structs: a base pointer plus an integer index
     scaled by a small power-of-two, followed by >=1 byte load and >=2 halfword
     loads from that base.
  3) Emits a summary (txt + json) with the inferred stride, offsets, and light
     usage hints (bit tests, bitfield ops, masked AND/TST, index uses) for the
     loaded fields.

See also: book/api/ghidra/README.md (node struct/evaluator tooling) and
book/api/ghidra/ghidra_lib/README.md (helper schema/usage).
"""

import json
import os

from ghidra_bootstrap import node_scan_utils

SCHEMA_VERSION = node_scan_utils.SCHEMA_VERSION
analyze_usage = node_scan_utils.analyze_usage
block_name = node_scan_utils.block_name
choose_index_and_base = node_scan_utils.choose_index_and_base
collect_loads = node_scan_utils.collect_loads
filter_loads = node_scan_utils.filter_loads
validate_candidate_schema = node_scan_utils.validate_candidate_schema

DEFAULT_EVAL = "fffffe000b40d698"


def build_reachable_from_eval(eval_entry):
    fm = currentProgram.getFunctionManager()
    start_func = getFunctionAt(eval_entry)
    if start_func is None:
        return set()
    reachable = set()
    work = [start_func]
    while work:
        f = work.pop()
        if f in reachable:
            continue
        reachable.add(f)
        listing = currentProgram.getListing()
        instr_iter = listing.getInstructions(f.getBody(), True)
        for ins in instr_iter:
            try:
                ft = ins.getFlowType()
                if ft is None or not ft.isCall():
                    continue
                for dest in ins.getFlows():
                    callee = getFunctionAt(dest)
                    if callee and callee not in reachable:
                        work.append(callee)
            except Exception:
                continue
    return reachable


def scan_function(func):
    load_records = collect_loads(func, currentProgram)
    index_reg, stride, base_reg = choose_index_and_base(load_records)
    if not index_reg or not base_reg:
        return None
    filtered = filter_loads(load_records, base_reg, index_reg, stride)
    byte_offs = [l["offset"] for l in filtered if l["width"] == 1]
    half_offs = [l["offset"] for l in filtered if l["width"] == 2]
    if len(byte_offs) < 1 or len(half_offs) < 2:
        return None
    usage = analyze_usage(func, filtered)
    return {
        "function": func.getName(),
        "entry": str(func.getEntryPoint()),
        "block": block_name(func),
        "index_reg": index_reg,
        "stride": stride,
        "base_reg": base_reg,
        "byte_offsets": sorted(list(set(byte_offs))),
        "half_offsets": sorted(list(set(half_offs))),
        "loads": filtered,
        "usage": usage,
        "instruction_count": len(list(currentProgram.getListing().getInstructions(func.getBody(), True))),
    }


def parse_eval(arg):
    if not arg:
        return toAddr(DEFAULT_EVAL)
    try:
        return toAddr(arg)
    except Exception:
        funcs = getGlobalFunctions(arg)
        if funcs:
            return funcs[0].getEntryPoint()
    return None


def write_reports(out_dir, candidates, scanned_count, eval_entry):
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    txt_path = os.path.join(out_dir, "node_struct_scan.txt")
    json_path = os.path.join(out_dir, "node_struct_scan.json")
    lines = []
    lines.append("== Node struct scan (reachable from _eval) ==")
    lines.append("Candidates: %d (functions scanned: %d)" % (len(candidates), scanned_count))
    for cand in candidates:
        lines.append(
            "%s (%s)%s: base=%s index=%s stride=%s bytes=%s halfs=%s"
            % (
                cand["function"],
                cand["entry"],
                " block=%s" % cand["block"] if cand.get("block") else "",
                cand["base_reg"],
                cand["index_reg"],
                hex(cand["stride"]) if cand["stride"] else "unknown",
                [hex(x) for x in cand["byte_offsets"]],
                [hex(x) for x in cand["half_offsets"]],
            )
        )
        if cand["usage"]:
            lines.append("  usage hints:")
            for u in cand["usage"]:
                lines.append("    %s %s flags=%s" % (u["insn"], u["disasm"], ",".join(u["flags"])))
    with open(txt_path, "w") as fh:
        fh.write("\n".join(lines))
    payload = {
        "schema_version": SCHEMA_VERSION,
        "eval_entry": str(eval_entry),
        "functions_scanned": scanned_count,
        "candidates": [c for c in candidates if validate_candidate_schema(c)],
    }
    with open(json_path, "w") as fh:
        json.dump(payload, fh, indent=2)
    print("[+] wrote reports to %s and %s" % (txt_path, json_path))


def run():
    args = getScriptArgs()
    if not args or args[0] != "scan":
        printerr("Usage: kernel_node_struct_scan.py scan <out_dir> [eval_fn_or_addr]")
        return
    if len(args) < 2:
        printerr("Usage: kernel_node_struct_scan.py scan <out_dir> [eval_fn_or_addr]")
        return
    out_dir = args[1]
    eval_arg = args[2] if len(args) > 2 else None
    eval_entry = parse_eval(eval_arg)
    if eval_entry is None:
        printerr("Could not resolve eval entry")
        return
    reachable = build_reachable_from_eval(eval_entry)
    reachable_count = len(reachable)
    candidates = []
    for func in reachable:
        res = scan_function(func)
        if res:
            candidates.append(res)
    candidates.sort(key=lambda c: (-len(c["half_offsets"]), c["function"]))
    write_reports(out_dir, candidates, reachable_count, eval_entry)


run()
