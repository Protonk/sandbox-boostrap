#@category Sandbox
"""
Dump disassembly for one or more functions or addresses.
Args: <out_dir> <build_id> <addr_or_name> [more...]

Each argument is either:
  - Hex address (with or without 0x) to find the containing function, or
  - Function name.

Outputs JSON to <out_dir>/function_dump.json with per-function instruction lists.

Pitfalls: requires functions recovered for name-based lookup; avoid --no-analysis if you rely on names. Address targets are resolved even without names but benefit from proper processor import.
Notes:
- The instruction list is capped to keep JSON outputs bounded and diffable.
- Function lookup by name scans the whole function manager; keep target lists small.
"""

import json
import os
import traceback

from ghidra_bootstrap import io_utils, scan_utils

_RUN_CALLED = False


def _ensure_out_dir(path):
    return io_utils.ensure_out_dir(path)

def _parse_targets(tokens):
    addrs = []
    names = []
    for t in tokens:
        try:
            addrs.append(scan_utils.parse_hex(str(t)))
        except Exception:
            names.append(str(t))
    return addrs, names


def _find_function_by_name(func_mgr, name):
    # Ghidra API lacks direct name lookup; scan all functions once.
    funcs = func_mgr.getFunctions(True)
    while funcs.hasNext():
        func = funcs.next()
        if func.getName() == name:
            return func
    return None


def _dump_function(func, listing):
    instr_iter = listing.getInstructions(func.getBody(), True)
    lines = []

    def _bytes_hex(obj):
        if obj is None:
            return None
        try:
            return bytes(obj).hex()
        except Exception:
            try:
                return str(obj)
            except Exception:
                return None

    while instr_iter.hasNext() and not monitor.isCancelled():
        instr = instr_iter.next()
        bytes_at = None
        try:
            bytes_at = instr.getBytes()
        except Exception:
            bytes_at = None
            lines.append(
            {
                "addr": scan_utils.format_address(instr.getAddress().getOffset()),
                "mnemonic": instr.getMnemonicString(),
                "inst": str(instr),
                "bytes": _bytes_hex(bytes_at),
            }
        )
        if len(lines) > 4000:
            # Cap output size to keep snapshots reviewable.
            lines.append({"truncated": True})
            break
    return lines


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_function_dump.py <out_dir> <build_id> <addr_or_name> [more]")
            return
        out_dir = args[0]
        build_id = args[1]
        addr_tokens = args[2:]
        _ensure_out_dir(out_dir)
        listing = currentProgram.getListing()
        func_mgr = currentProgram.getFunctionManager()
        addr_factory = currentProgram.getAddressFactory()
        addr_vals, name_vals = _parse_targets(addr_tokens)
        entries = []
        for a in addr_vals:
            addr = addr_factory.getDefaultAddressSpace().getAddress(scan_utils.format_address(a))
            func = func_mgr.getFunctionContaining(addr)
            if not func:
                entries.append({"input": scan_utils.format_address(a), "error": "no function at address"})
                continue
            entries.append(
                {
                    "input": scan_utils.format_address(a),
                    "function": func.getName(),
                    "entry": scan_utils.format_address(func.getEntryPoint().getOffset()),
                    "instructions": _dump_function(func, listing),
                }
            )
        for name in name_vals:
            func = _find_function_by_name(func_mgr, name)
            if not func:
                entries.append({"input": name, "error": "function not found"})
                continue
            entries.append(
                {
                    "input": name,
                    "function": func.getName(),
                    "entry": scan_utils.format_address(func.getEntryPoint().getOffset()),
                    "instructions": _dump_function(func, listing),
                }
            )
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "target_count": len(addr_tokens),
        }
        with open(os.path.join(out_dir, "function_dump.json"), "w") as f:
            json.dump({"meta": meta, "entries": entries}, f, indent=2, sort_keys=True)
        print("kernel_function_dump: dumped %d entries" % len(entries))
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
