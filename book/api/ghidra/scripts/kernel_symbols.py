#@category Sandbox
"""
Import BootKernelExtensions.kc, focus on com.apple.security.sandbox blocks, and emit symbol/string tables.
Outputs land under book/dumps/ghidra/out/<build>/kernel-symbols/.

Args (from scaffold): <out_dir> [build_id]
Pitfalls: with --no-analysis you still get symbol tables but fewer functions; block filtering prefers sandbox-named blocks, falls back to full program if unnamed.
Notes:
- Symbols/strings are filtered to sandbox blocks to keep outputs targeted.
- Provenance is required for canonical fixture freshness checks.
"""

import json
import os
import traceback

from ghidra_bootstrap import block_utils, io_utils, provenance, scan_utils

from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import StringDataInstance
from ghidra.program.model.symbol import SymbolType

_RUN_CALLED = False


def _ensure_out_dir(path):
    return io_utils.ensure_out_dir(path)

def _sandbox_blocks():
    return block_utils.sandbox_blocks(program=currentProgram)

def _block_set(blocks):
    return block_utils.block_set(blocks)

def _build_provenance(build_id, block_mode, block_count):
    script_path = os.path.realpath(__file__)
    profile_id = os.environ.get("SANDBOX_LORE_GHIDRA_PROFILE_ID")
    if not profile_id:
        # Profile id encodes block mode/count so outputs can be compared across runs.
        profile_id = "kernel_symbols:block_mode=%s:blocks=%d" % (block_mode, block_count)

    program_name = currentProgram.getName()
    return provenance.build_provenance(build_id, profile_id, script_path, program_name=program_name)


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
            "address": scan_utils.format_address(addr.getOffset()),
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
                "address": scan_utils.format_address(addr.getOffset()),
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

        # Prefer sandbox-named blocks; block_utils falls back to all blocks if needed.
        blocks = _sandbox_blocks()
        addr_set = _block_set(blocks)
        block_meta = block_utils.block_meta(blocks)
        block_mode = block_utils.block_mode(blocks)
        provenance = _build_provenance(build_id, block_mode, len(blocks))

        symbols = _collect_symbols(addr_set)
        strings = _collect_strings(addr_set)
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "block_filter": block_meta,
            "symbol_count": len(symbols),
            "string_count": len(strings),
        }

        io_utils.write_json(os.path.join(out_dir, "symbols.json"), {"_provenance": provenance, "meta": meta, "symbols": symbols})
        io_utils.write_json(os.path.join(out_dir, "strings.json"), {"_provenance": provenance, "meta": meta, "strings": strings})

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
