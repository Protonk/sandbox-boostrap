#@category Sandbox
"""
Import BootKernelExtensions.kc, focus on com.apple.security.sandbox blocks, and emit symbol/string tables.
Outputs land under dumps/ghidra/out/<build>/kernel-symbols/.
"""

import json
import os
import traceback

from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import StringDataInstance
from ghidra.program.model.symbol import SymbolType

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


def _block_set(blocks):
    aset = AddressSet()
    for blk in blocks:
        aset.add(blk.getStart(), blk.getEnd())
    return aset


def _collect_symbols(address_set):
    symtab = currentProgram.getSymbolTable()
    memory = currentProgram.getMemory()
    iterator = symtab.getSymbolIterator(True)
    out = []
    while iterator.hasNext() and not monitor.isCancelled():
        sym = iterator.next()
        addr = sym.getAddress()
        if address_set and not address_set.contains(addr):
            continue
        block = memory.getBlock(addr)
        entry = {
            "name": sym.getName(),
            "type": sym.getSymbolType().toString(),
            "address": "0x%x" % addr.getOffset(),
            "namespace": sym.getParentNamespace().getName(True),
            "block": block.getName() if block else None,
        }
        if sym.getSymbolType() == SymbolType.FUNCTION:
            func = currentProgram.getFunctionManager().getFunctionAt(addr)
            if func:
                entry["function_size"] = func.getBody().getNumAddresses()
        out.append(entry)
    return out


def _collect_strings(address_set):
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
    data_iter = listing.getDefinedData(True)
    out = []
    while data_iter.hasNext() and not monitor.isCancelled():
        data = data_iter.next()
        addr = data.getAddress()
        if not address_set.contains(addr):
            continue
        if not StringDataInstance.isString(data):
            continue
        sval = data.getValue()
        if sval is None:
            continue
        block = memory.getBlock(addr)
        out.append(
            {
                "address": "0x%x" % addr.getOffset(),
                "value": str(sval),
                "block": block.getName() if block else None,
            }
        )
    return out


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 1:
            print("usage: kernel_symbols.py <out_dir> [build_id]")
            return
        out_dir = args[0]
        build_id = args[1] if len(args) > 1 else ""
        print("kernel_symbols: starting for build %s -> %s" % (build_id, out_dir))

        _ensure_out_dir(out_dir)
        trace_path = os.path.join(out_dir, "trace.log")
        with open(trace_path, "a") as trace:
            trace.write("start\n")

        blocks = _sandbox_blocks()
        addr_set = _block_set(blocks)
        block_meta = [
            {
                "name": blk.getName(),
                "start": "0x%x" % blk.getStart().getOffset(),
                "end": "0x%x" % blk.getEnd().getOffset(),
            }
            for blk in blocks
        ]

        symbols = _collect_symbols(addr_set)
        strings = _collect_strings(addr_set)
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "block_filter": block_meta,
            "symbol_count": len(symbols),
            "string_count": len(strings),
        }

        with open(os.path.join(out_dir, "symbols.json"), "w") as f:
            json.dump({"meta": meta, "symbols": symbols}, f, indent=2, sort_keys=True)
        with open(os.path.join(out_dir, "strings.json"), "w") as f:
            json.dump({"meta": meta, "strings": strings}, f, indent=2, sort_keys=True)

        print("kernel_symbols: wrote %d symbols and %d strings to %s" % (len(symbols), len(strings), out_dir))
        with open(trace_path, "a") as trace:
            trace.write("done\n")
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
