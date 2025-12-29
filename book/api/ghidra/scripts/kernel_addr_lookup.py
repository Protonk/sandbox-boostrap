#@category Sandbox
"""
Lookup file offsets or constant patterns in the current program and report addresses/functions/callers.
Args:
  <out_dir> [build_id] [offsets/addresses...] [--data-only]
Offsets are hex without 0x (file offsets, added to image base). Prefix an input with
  'addr:' to treat it as an absolute address instead. Outputs JSON to out_dir/addr_lookup.json.
When --data-only is present, report defined data at the computed address (type/value).

Pitfalls: file-offset math assumes correct image base; ensure the KC was imported with the right processor/format. Caller/callee info requires functions (avoid --no-analysis if you need it).
"""

import json
import os
import traceback

from ghidra_bootstrap import scan_utils

_RUN_CALLED = False


def _ensure_out_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _lookup_offsets(offsets):
    res = []
    memory = currentProgram.getMemory()
    func_mgr = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()
    listing = currentProgram.getListing()
    addr_factory = currentProgram.getAddressFactory()
    img_base_addr = currentProgram.getImageBase()
    img_base = img_base_addr.getOffset()
    for off, is_addr in offsets:
        if is_addr:
            addr = addr_factory.getDefaultAddressSpace().getAddress(scan_utils.format_address(off))
            file_offset = None
        else:
            file_offset = scan_utils.format_address(off)
            try:
                addr = img_base_addr.add(off)
            except Exception:
                addr = addr_factory.getDefaultAddressSpace().getAddress(scan_utils.format_address(img_base + off))
        block = memory.getBlock(addr)
        data_entry = listing.getDataAt(addr)
        func = func_mgr.getFunctionContaining(addr)
        refs = ref_mgr.getReferencesTo(addr)
        callers = []
        for ref in refs:
            from_addr = ref.getFromAddress()
            caller = func_mgr.getFunctionContaining(from_addr)
            callers.append(
                {
                    "from": scan_utils.format_address(from_addr.getOffset()),
                    "type": ref.getReferenceType().getName(),
                    "caller": caller.getName() if caller else None,
                }
            )
        instr = listing.getInstructionAt(addr)
        bytes_at = None
        if instr:
            try:
                bytes_at = instr.getBytes()
            except Exception:
                bytes_at = None
        res.append(
            {
                "input": file_offset or ("addr:%s" % scan_utils.format_address(off)),
                "address": scan_utils.format_address(addr.getOffset()),
                "image_base": scan_utils.format_address(img_base),
                "block": block.getName() if block else None,
                "function": func.getName() if func else None,
                "instruction": str(instr) if instr else None,
                "bytes": bytes_at.hex() if bytes_at else None,
                "data_type": data_entry.getDataType().getName() if data_entry else None,
                "data_value": str(data_entry.getValue()) if data_entry else None,
                "callers": callers,
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
        if len(args) < 2:
            print("usage: kernel_addr_lookup.py <out_dir> <build_id> [offsets...] [--data-only]")
            return
        out_dir = args[0]
        build_id = args[1]
        offsets = []
        data_only = False
        for x in args[2:]:
            if str(x) == "--data-only":
                data_only = True
                continue
            try:
                token = str(x)
                if token.startswith("addr:"):
                    offsets.append((scan_utils.parse_hex(token.split("addr:", 1)[1]), True))
                else:
                    offsets.append((scan_utils.parse_hex(token), False))
            except Exception:
                print("skip arg %s (not an offset)" % x)
                continue
        _ensure_out_dir(out_dir)
        print("kernel_addr_lookup: inputs=%s data_only=%s" % (offsets, data_only))
        results = _lookup_offsets(offsets)
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "offset_count": len(offsets),
            "data_only": data_only,
        }
        with open(os.path.join(out_dir, "addr_lookup.json"), "w") as f:
            json.dump({"meta": meta, "results": results}, f, indent=2, sort_keys=True)
        print("kernel_addr_lookup: wrote %d results" % len(results))
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
