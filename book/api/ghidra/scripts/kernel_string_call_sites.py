#@category Sandbox
"""
Find functions that reference specific strings and list call sites to them.

Args: <out_dir> <build_id> [all] <query...>
  - include "all" to scan all memory blocks (default: sandbox blocks only)
  - queries are substring matches against defined strings

Outputs: <out_dir>/string_call_sites.json
"""

import json
import os
import traceback

from ghidra.program.model.address import Address, AddressSet
from ghidra.program.model.data import StringDataInstance

_RUN = False
MASK64 = 0xFFFFFFFFFFFFFFFFL
SIGN_BIT = 0x8000000000000000L


def _ensure_out_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _sandbox_blocks():
    mem = currentProgram.getMemory()
    blocks = []
    for blk in mem.getBlocks():
        name = blk.getName() or ""
        if "sandbox" in name.lower():
            blocks.append(blk)
    if blocks:
        return blocks
    return list(mem.getBlocks())


def _block_set(blocks):
    aset = AddressSet()
    for blk in blocks:
        aset.add(blk.getStart(), blk.getEnd())
    return aset


def _collect_refs(addr, addr_set, func_mgr, memory, ref_mgr):
    refs = []
    for ref in ref_mgr.getReferencesTo(addr):
        from_addr = ref.getFromAddress()
        if addr_set and not addr_set.isEmpty() and not addr_set.contains(from_addr):
            continue
        func = func_mgr.getFunctionContaining(from_addr)
        block = memory.getBlock(from_addr)
        refs.append(
            {
                "from": "0x%x" % from_addr.getOffset(),
                "type": ref.getReferenceType().getName(),
                "function": func.getName() if func else None,
                "function_entry": "0x%x" % func.getEntryPoint().getOffset() if func else None,
                "block": block.getName() if block else None,
            }
        )
    return refs


def _s64(val):
    try:
        v = long(val) & MASK64
    except Exception:
        return None
    if v & SIGN_BIT:
        return v - (1 << 64)
    return v


def _parse_hex(text):
    text = str(text).strip().lower()
    if not text:
        return None
    if text.startswith("0x-"):
        return -int(text[3:], 16)
    if text.startswith("-0x"):
        return -int(text[3:], 16)
    if text.startswith("0x"):
        value = int(text, 16)
        if value & (1 << 63):
            return value - (1 << 64)
        return value
    value = int(text, 0)
    if value & (1 << 63):
        return value - (1 << 64)
    return value


def run():
    global _RUN
    if _RUN:
        return
    _RUN = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_string_call_sites.py <out_dir> <build_id> [all] <query...>")
            return
        out_dir = args[0]
        build_id = args[1]
        scan_all = False
        queries = []
        for item in args[2:]:
            val = str(item)
            if val.lower() == "all":
                scan_all = True
                continue
            queries.append(val)
        if not queries:
            print("No query strings provided.")
            return

        _ensure_out_dir(out_dir)
        memory = currentProgram.getMemory()
        func_mgr = currentProgram.getFunctionManager()
        ref_mgr = currentProgram.getReferenceManager()
        listing = currentProgram.getListing()

        blocks = list(memory.getBlocks()) if scan_all else _sandbox_blocks()
        addr_set = _block_set(blocks)

        string_hits = []
        func_hits = {}
        data_iter = listing.getDefinedData(True)
        while data_iter.hasNext() and not monitor.isCancelled():
            data = data_iter.next()
            if not StringDataInstance.isString(data):
                continue
            sval = data.getValue()
            if sval is None:
                continue
            sval = str(sval)
            matched = [q for q in queries if q in sval]
            if not matched:
                continue
            addr = data.getAddress()
            block = memory.getBlock(addr)
            refs = _collect_refs(addr, addr_set, func_mgr, memory, ref_mgr)
            string_hits.append(
                {
                    "address": "0x%x" % addr.getOffset(),
                    "value": sval,
                    "block": block.getName() if block else None,
                    "queries": matched,
                    "reference_count": len(refs),
                    "references": refs,
                }
            )
            for ref in refs:
                entry = ref.get("function_entry")
                if not entry:
                    continue
                func_hits.setdefault(entry, {"entry": entry, "name": ref.get("function"), "strings": set()})
                func_hits[entry]["strings"].add(sval)

        call_sites = []
        for entry_hex, info in func_hits.items():
            entry_val = _parse_hex(entry_hex)
            if entry_val is None:
                continue
            entry_addr = toAddr(_s64(entry_val))
            if entry_addr is None:
                continue
            for ref in ref_mgr.getReferencesTo(entry_addr):
                rtype = ref.getReferenceType()
                if not rtype.isCall():
                    continue
                call_addr = ref.getFromAddress()
                if addr_set and not addr_set.contains(call_addr):
                    continue
                instr = listing.getInstructionAt(call_addr)
                block = memory.getBlock(call_addr)
                call_sites.append(
                    {
                        "call_address": "0x%x" % call_addr.getOffset(),
                        "call_mnemonic": instr.getMnemonicString() if instr else None,
                        "target_entry": entry_hex,
                        "target_name": info.get("name"),
                        "block": block.getName() if block else None,
                    }
                )

        out = {
            "meta": {
                "build_id": build_id,
                "program": currentProgram.getName(),
                "query_strings": queries,
                "scan_all_blocks": scan_all,
                "string_hit_count": len(string_hits),
                "function_hit_count": len(func_hits),
                "call_site_count": len(call_sites),
            },
            "string_hits": string_hits,
            "functions": [
                {"entry": k, "name": v.get("name"), "strings": sorted(v.get("strings") or [])}
                for k, v in sorted(func_hits.items())
            ],
            "call_sites": call_sites,
        }
        with open(os.path.join(out_dir, "string_call_sites.json"), "w") as f:
            json.dump(out, f, indent=2, sort_keys=True)
        print("kernel_string_call_sites: wrote %d call sites" % len(call_sites))
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
