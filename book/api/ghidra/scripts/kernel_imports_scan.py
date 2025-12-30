#@category Sandbox
"""
Enumerate external symbols (imports) in the KC and record references/callers.

Args: <out_dir> [build_id] [substr ...]
- When substrings are provided, only include externals whose name or library contains any substring (case-insensitive).
- If no substrings are provided, include all externals.

Outputs: book/dumps/ghidra/out/<build>/kernel-imports/external_symbols.json
Schema: meta (build_id, program, substrings, counts), symbols (name, library, type, address, block, references[]).

Notes:
- No block filtering; scans the full program for externals.
- References include caller function names when available.
 - External symbol locations can be missing in partially analyzed projects.
"""

import json
import os
import traceback

from ghidra_bootstrap import scan_utils

_RUN = False


def _ensure(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _safe_external_location(sym):
    try:
        return sym.getExternalLocation()
    except Exception:
        return None


def _collect_refs(addr, func_mgr, memory, ref_mgr):
    refs = []
    for ref in ref_mgr.getReferencesTo(addr):
        from_addr = ref.getFromAddress()
        func = func_mgr.getFunctionContaining(from_addr)
        block = memory.getBlock(from_addr)
        refs.append(
            {
                "from": scan_utils.format_address(from_addr.getOffset()),
                "type": ref.getReferenceType().getName(),
                "is_primary": ref.isPrimary(),
                "function": func.getName() if func else None,
                "block": block.getName() if block else None,
            }
        )
    return refs


def run():
    global _RUN
    if _RUN:
        return
    _RUN = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 1:
            print("usage: kernel_imports_scan.py <out_dir> [build_id] [substr ...]")
            return
        out_dir = args[0]
        build_id = args[1] if len(args) > 1 else ""
        # Lowercase filters once so matching is case-insensitive.
        substrings = [s.lower() for s in args[2:]] if len(args) > 2 else []
        _ensure(out_dir)

        symtab = currentProgram.getSymbolTable()
        func_mgr = currentProgram.getFunctionManager()
        memory = currentProgram.getMemory()
        ref_mgr = currentProgram.getReferenceManager()

        matches = []
        sym_iter = symtab.getExternalSymbols()
        while sym_iter.hasNext() and not monitor.isCancelled():
            sym = sym_iter.next()
            loc = _safe_external_location(sym)
            if not loc:
                continue
            lib = loc.getLibraryName() or ""
            name = sym.getName() or ""
            if substrings:
                if not any(sub in name.lower() or sub in lib.lower() for sub in substrings):
                    continue
            addr = sym.getAddress()
            refs = _collect_refs(addr, func_mgr, memory, ref_mgr)
            block = memory.getBlock(addr)
            matches.append(
                {
                    "name": name,
                    "library": lib,
                    "type": sym.getSymbolType().toString(),
                    "address": scan_utils.format_address(addr.getOffset()),
                    "block": block.getName() if block else None,
                    "references": refs,
                }
            )

        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "query_substrings": substrings,
            "symbol_count": len(matches),
        }
        with open(os.path.join(out_dir, "external_symbols.json"), "w") as f:
            json.dump({"meta": meta, "symbols": matches}, f, indent=2, sort_keys=True)
        print("kernel_imports_scan: wrote %d symbols to %s" % (len(matches), out_dir))
    except Exception:
        if out_dir:
            try:
                _ensure(out_dir)
                with open(os.path.join(out_dir, "error.log"), "w") as err:
                    traceback.print_exc(file=err)
            except Exception:
                pass
        traceback.print_exc()


if not os.environ.get("GHIDRA_SKIP_AUTORUN"):
    # Allow callers to import this script without running it.
    run()
