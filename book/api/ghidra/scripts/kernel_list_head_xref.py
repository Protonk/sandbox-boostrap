#@category Sandbox
"""
Enumerate references to a list head address and group by function.
Args: <out_dir> <build_id> <addr_hex>

Outputs: <out_dir>/list_head_xref.json

Notes:
- Reference types include read/write flags from Ghidra's ReferenceType API.
- Grouping by function helps identify writers vs readers quickly.
"""

import json
import os
import traceback

from ghidra_bootstrap import io_utils, scan_utils


_RUN_CALLED = False


def _ensure_out_dir(path):
    return io_utils.ensure_out_dir(path)

def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_list_head_xref.py <out_dir> <build_id> <addr_hex>")
            return
        out_dir = args[0]
        build_id = args[1]
        addr_val = scan_utils.parse_hex(args[2])
        if addr_val is None:
            raise ValueError("Invalid address: %s" % args[2])

        _ensure_out_dir(out_dir)
        addr_factory = currentProgram.getAddressFactory()
        addr_space = addr_factory.getDefaultAddressSpace()
        addr = addr_space.getAddress(scan_utils.format_address(addr_val))
        ref_mgr = currentProgram.getReferenceManager()
        func_mgr = currentProgram.getFunctionManager()

        refs = []
        for ref in ref_mgr.getReferencesTo(addr):
            from_addr = ref.getFromAddress()
            func = func_mgr.getFunctionContaining(from_addr)
            refs.append(
                {
                    "from": scan_utils.format_address(from_addr.getOffset()),
                    "function": func.getName() if func else None,
                    "type": ref.getReferenceType().getName(),
                    "is_read": ref.getReferenceType().isRead(),
                    "is_write": ref.getReferenceType().isWrite(),
                }
            )

        grouped = {}
        for ref in refs:
            # Use <no-func> for raw references that aren't inside a recovered function.
            func = ref.get("function") or "<no-func>"
            grouped.setdefault(func, []).append(ref)

        out = {
            "build_id": build_id,
            "address": scan_utils.format_address(addr_val),
            "ref_count": len(refs),
            "refs": refs,
            "refs_by_function": grouped,
        }
        with open(os.path.join(out_dir, "list_head_xref.json"), "w") as f:
            json.dump(out, f, indent=2, sort_keys=True)
        print("kernel_list_head_xref: wrote %d refs" % len(refs))
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
