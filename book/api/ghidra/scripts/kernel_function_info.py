#@category Sandbox
"""
Emit metadata for specified functions: address, size, callers, callees.
Args: <out_dir> <build_id> <function_name> [function_name...]

Outputs: <out_dir>/function_info.json with per-function metadata.
Pitfalls: depends on symbol/function recovery; avoid --no-analysis if you need caller/callee sets populated.
"""

import json
import os
import traceback

from ghidra_bootstrap import scan_utils

_RUN_CALLED = False


def _ensure_out_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _collect_for_name(name):
    symtab = currentProgram.getSymbolTable()
    func_mgr = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()
    memory = currentProgram.getMemory()
    res = []
    func = None
    sym_iter = symtab.getSymbols(name)
    while sym_iter.hasNext() and not monitor.isCancelled():
        sym = sym_iter.next()
        func = func_mgr.getFunctionAt(sym.getAddress())
        if func:
            break
    if func:
        callers = []
        for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
            caller_func = func_mgr.getFunctionContaining(ref.getFromAddress())
                callers.append(
                {
                    "from": scan_utils.format_address(ref.getFromAddress().getOffset()),
                    "type": ref.getReferenceType().getName(),
                    "caller": caller_func.getName() if caller_func else None,
                }
            )
        callees = []
        for ref in ref_mgr.getReferencesFrom(func.getEntryPoint()):
            callee = func_mgr.getFunctionAt(ref.getToAddress())
            if callee:
                callees.append(callee.getName())
        block = memory.getBlock(func.getEntryPoint())
        res.append(
            {
                "name": func.getName(),
                "address": scan_utils.format_address(func.getEntryPoint().getOffset()),
                "block": block.getName() if block else None,
                "size": func.getBody().getNumAddresses(),
                "callers": callers,
                "callees": sorted(set(callees)),
            }
        )
    return res


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_function_info.py <out_dir> <build_id> <function_name> [function_name...]")
            return
        out_dir = args[0]
        build_id = args[1]
        names = [n for n in args[2:] if not n.startswith("-")]
        _ensure_out_dir(out_dir)
        results = []
        for name in names:
            results.extend(_collect_for_name(name))
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "query_names": names,
            "result_count": len(results),
        }
        with open(os.path.join(out_dir, "function_info.json"), "w") as f:
            json.dump({"meta": meta, "results": results}, f, indent=2, sort_keys=True)
        print("kernel_function_info: wrote %d results" % len(results))
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
