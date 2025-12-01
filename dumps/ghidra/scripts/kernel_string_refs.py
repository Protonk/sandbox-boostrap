#@category Sandbox
"""
Walk references to key sandbox strings and AppleMatch imports.
Outputs JSON under dumps/ghidra/out/<build>/kernel-string-refs/.
"""

import json
import os
import traceback

from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import StringDataInstance

_RUN_CALLED = False


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


def _collect_refs(addr, addr_set, func_mgr, memory, ref_mgr):
    refs = []
    for ref in ref_mgr.getReferencesTo(addr):
        from_addr = ref.getFromAddress()
        if addr_set and not addr_set.contains(from_addr):
            continue
        func = func_mgr.getFunctionContaining(from_addr)
        block = memory.getBlock(from_addr)
        refs.append(
            {
                "from": "0x%x" % from_addr.getOffset(),
                "type": ref.getReferenceType().getName(),
                "is_primary": ref.isPrimary(),
                "function": func.getName() if func else None,
                "block": block.getName() if block else None,
            }
        )
    return refs


def _string_matches(queries, addr_set):
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
    func_mgr = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()
    matches = []
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
        matches.append(
            {
                "address": "0x%x" % addr.getOffset(),
                "value": sval,
                "block": block.getName() if block else None,
                "queries": matched,
                "references": refs,
            }
        )
    return matches


def _symbols_matching(substr, addr_set):
    symtab = currentProgram.getSymbolTable()
    memory = currentProgram.getMemory()
    func_mgr = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()
    matches = []
    seen = set()
    sym_iter = symtab.getSymbolIterator(True)
    while sym_iter.hasNext() and not monitor.isCancelled():
        sym = sym_iter.next()
        name = sym.getName() or ""
        if substr not in name.lower():
            continue
        addr = sym.getAddress()
        key = (name, addr.getOffset())
        if key in seen:
            continue
        seen.add(key)
        refs = _collect_refs(addr, addr_set, func_mgr, memory, ref_mgr)
        block = memory.getBlock(addr)
        matches.append(
            {
                "name": name,
                "type": sym.getSymbolType().toString(),
                "address": "0x%x" % addr.getOffset(),
                "namespace": sym.getParentNamespace().getName(True),
                "block": block.getName() if block else None,
                "references": refs,
            }
        )
    return matches


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 1:
            print("usage: kernel_string_refs.py <out_dir> [build_id]")
            return
        out_dir = args[0]
        build_id = args[1] if len(args) > 1 else ""
        print("kernel_string_refs: starting for build %s -> %s" % (build_id, out_dir))

        _ensure_out_dir(out_dir)
        queries = ["com.apple.security.sandbox", "com.apple.kext.AppleMatch"]

        blocks = _sandbox_blocks()
        addr_set = AddressSet()
        for blk in blocks:
            addr_set.add(blk.getStart(), blk.getEnd())
        block_meta = [
            {
                "name": blk.getName(),
                "start": "0x%x" % blk.getStart().getOffset(),
                "end": "0x%x" % blk.getEnd().getOffset(),
            }
            for blk in blocks
        ]

        string_hits = _string_matches(queries, addr_set)
        apple_match_syms = _symbols_matching("applematch", addr_set)
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "block_filter": block_meta,
            "query_strings": queries,
            "string_hits": len(string_hits),
            "applematch_symbols": len(apple_match_syms),
        }

        with open(os.path.join(out_dir, "string_references.json"), "w") as f:
            json.dump({"meta": meta, "strings": string_hits, "applematch_symbols": apple_match_syms}, f, indent=2, sort_keys=True)

        print(
            "kernel_string_refs: found %d string hits and %d AppleMatch symbols (filtered to sandbox blocks)"
            % (len(string_hits), len(apple_match_syms))
        )
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
