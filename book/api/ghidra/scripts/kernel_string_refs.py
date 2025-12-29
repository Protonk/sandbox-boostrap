#@category Sandbox
"""
Walk references to key sandbox strings and AppleMatch imports.
Outputs JSON under dumps/ghidra/out/<build>/kernel-string-refs/.
Args: <out_dir> [build_id] [all] [extra queries...]
  - include "all" to scan all memory blocks (default: sandbox blocks only)
  - provide extra query substrings to match additional strings

Pitfalls:
- Relies on defined string data; with --no-analysis strings may be sparse. Run at least an import pass that defines data.
- Filters to sandbox blocks unless "all" is passed to reduce noise.
Notes:
- Default queries focus on sandbox and AppleMatch strings; extra queries extend the search.
- String refs are substring matches to keep the scan flexible.
"""

import json
import os
import traceback

from ghidra_bootstrap import block_utils, io_utils, scan_utils

from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import StringDataInstance

_RUN_CALLED = False


def _ensure_out_dir(path):
    return io_utils.ensure_out_dir(path)

def _sandbox_blocks():
    return block_utils.sandbox_blocks(program=currentProgram)

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
                "from": scan_utils.format_address(from_addr.getOffset()),
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
        # Substring match keeps the search resilient to small string edits.
        matched = [q for q in queries if q in sval]
        if not matched:
            continue
        addr = data.getAddress()
        block = memory.getBlock(addr)
        refs = _collect_refs(addr, addr_set, func_mgr, memory, ref_mgr)
        matches.append(
            {
                "address": scan_utils.format_address(addr.getOffset()),
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
                "address": scan_utils.format_address(addr.getOffset()),
                "namespace": sym.getParentNamespace().getName(True),
                "block": block.getName() if block else None,
                "references": refs,
            }
        )
    return matches


def _external_library_summary():
    symtab = currentProgram.getSymbolTable()
    libs = {}
    sym_iter = symtab.getExternalSymbols()
    while sym_iter.hasNext() and not monitor.isCancelled():
        sym = sym_iter.next()
        loc = _safe_external_location(sym)
        if not loc:
            continue
        lib = loc.getLibraryName() or ""
        libs[lib] = libs.get(lib, 0) + 1
    summary = []
    for lib, count in sorted(libs.items(), key=lambda kv: kv[0].lower()):
        summary.append({"library": lib, "symbol_count": count})
    return summary


def _safe_external_location(sym):
    """Return external location if available; tolerate FunctionSymbols lacking getExternalLocation."""
    try:
        return sym.getExternalLocation()
    except Exception:
        return None


def _external_functions(library_substr, addr_set):
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
        lib = (loc.getLibraryName() or "").lower()
        if library_substr not in lib:
            continue
        addr = sym.getAddress()
        refs = _collect_refs(addr, addr_set, func_mgr, memory, ref_mgr)
        matches.append(
            {
                "name": sym.getName(),
                "library": loc.getLibraryName(),
                "type": sym.getSymbolType().toString(),
                "address": scan_utils.format_address(addr.getOffset()),
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
            print("usage: kernel_string_refs.py <out_dir> [build_id] [all] [extra queries...]")
            return
        out_dir = args[0]
        build_id = args[1] if len(args) > 1 else ""
        flags_and_queries = args[2:]
        print("kernel_string_refs: starting for build %s -> %s" % (build_id, out_dir))

        _ensure_out_dir(out_dir)
        # Default queries are the primary sandbox and AppleMatch markers.
        queries = ["com.apple.security.sandbox", "com.apple.kext.AppleMatch"]
        scan_all = False
        extra_queries = []
        extlib_substr = "applematch"
        sym_substrs = ["applematch"]
        for item in flags_and_queries:
            if item.lower() == "all":
                scan_all = True
                continue
            if item.lower().startswith("extlib="):
                extlib_substr = item.split("=", 1)[1].lower()
                continue
            if item.lower().startswith("symsub="):
                sym_substrs.append(item.split("=", 1)[1].lower())
                continue
            extra_queries.append(item)
        if extra_queries:
            queries.extend(extra_queries)

        blocks = list(currentProgram.getMemory().getBlocks()) if scan_all else _sandbox_blocks()
        addr_set = AddressSet()
        for blk in blocks:
            addr_set.add(blk.getStart(), blk.getEnd())
        block_meta = [
            {
                "name": blk.getName(),
                "start": scan_utils.format_address(blk.getStart().getOffset()),
                "end": scan_utils.format_address(blk.getEnd().getOffset()),
            }
            for blk in blocks
        ]

        string_hits = _string_matches(queries, addr_set)
        symbol_hits = []
        seen_symbols = set()
        for sub in sym_substrs:
            for match in _symbols_matching(sub, addr_set):
                key = (match["name"], match["address"])
                if key in seen_symbols:
                    continue
                seen_symbols.add(key)
                match["query"] = sub
                symbol_hits.append(match)
        apple_match_externals = _external_functions(extlib_substr, addr_set)
        library_summary = _external_library_summary()
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "block_filter": block_meta,
            "query_strings": queries,
            "string_hits": len(string_hits),
            "symbol_hits": len(symbol_hits),
            "applematch_externals": len(apple_match_externals),
            "scan_all_blocks": scan_all,
            "external_library_filter": extlib_substr,
            "symbol_substrings": sym_substrs,
            "external_library_count": len(library_summary),
        }

        with open(os.path.join(out_dir, "string_references.json"), "w") as f:
            json.dump(
                {
                    "meta": meta,
                    "strings": string_hits,
                    "symbol_hits": symbol_hits,
                    "applematch_externals": apple_match_externals,
                    "external_libraries": library_summary,
                },
                f,
                indent=2,
                sort_keys=True,
            )

        print(
            "kernel_string_refs: found %d string hits, %d symbol hits, %d externals (lib filter: %s)"
            % (len(string_hits), len(symbol_hits), len(apple_match_externals), extlib_substr)
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


if not os.environ.get("GHIDRA_SKIP_AUTORUN"):
    run()
