#@category Sandbox
"""
Sweep GOT blocks (__auth_got/__got/__auth_ptr), define QWORDs, and collect refs.

Args: <out_dir> <build_id> [with_refs_only] [all]
  with_refs_only: "1" to include only entries with refs (default: 0).
  all: scan all blocks (default: only sandbox-named blocks, fallback to all).

Outputs: <out_dir>/got_ref_sweep.json
"""

import json
import os
import traceback

from ghidra_bootstrap import scan_utils

from ghidra.program.model.data import DataUtilities, DataTypeConflictHandler
from ghidra.program.model.data import QWordDataType
from ghidra.program.model.mem import MemoryAccessException

_RUN = False


def _ensure(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _s64(val):
    return scan_utils.to_signed(val)


def _format_addr(value):
    return scan_utils.format_signed_hex(value)


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


def _find_got_blocks(blocks):
    got_blocks = []
    kinds = []
    for blk in blocks:
        name = (blk.getName() or "").lower()
        kind = None
        if "auth_got" in name:
            kind = "auth_got"
        elif "auth_ptr" in name:
            kind = "auth_ptr"
        elif "got" in name:
            kind = "got"
        if not kind:
            continue
        got_blocks.append(blk)
        kinds.append(kind)
    mode = "+".join(sorted(set(kinds))) if kinds else None
    return got_blocks, mode


def _read_ptr(memory, addr):
    if addr is None or addr == 0:
        return None
    try:
        return _s64(memory.getLong(addr))
    except (MemoryAccessException, Exception):
        return None


def run():
    global _RUN
    if _RUN:
        return
    _RUN = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 2:
            print("usage: kernel_got_ref_sweep.py <out_dir> <build_id> [with_refs_only] [all]")
            return
        out_dir = args[0]
        build_id = args[1]
        with_refs_only = False
        scan_all = False
        for extra in args[2:]:
            token = str(extra).lower()
            if token in ("1", "true", "yes", "with_refs_only"):
                with_refs_only = True
            elif token == "all":
                scan_all = True

        _ensure(out_dir)
        listing = currentProgram.getListing()
        dtm = currentProgram.getDataTypeManager()
        qdt = QWordDataType()
        ref_mgr = currentProgram.getReferenceManager()
        func_mgr = currentProgram.getFunctionManager()
        memory = currentProgram.getMemory()

        blocks = list(memory.getBlocks()) if scan_all else _sandbox_blocks()
        got_blocks, got_mode = _find_got_blocks(blocks)
        results = []
        counts = {"entries": 0, "with_refs": 0}

        for blk in got_blocks:
            start = blk.getStart()
            end = blk.getEnd()
            addr = start
            limit = end.getOffset() - 7
            while addr.getOffset() <= limit and not monitor.isCancelled():
                # Define data as QWORD
                try:
                    DataUtilities.createData(
                        currentProgram, addr, qdt, -1, False, DataTypeConflictHandler.DEFAULT_HANDLER
                    )
                except Exception:
                    pass
                data_entry = listing.getDataAt(addr)
                refs = list(ref_mgr.getReferencesTo(addr))
                callers = []
                for r in refs:
                    fa = r.getFromAddress()
                    func = func_mgr.getFunctionContaining(fa)
                    callers.append(
                        {
                            "from": _format_addr(_s64(fa.getOffset())),
                            "type": r.getReferenceType().getName(),
                            "function": func.getName() if func else None,
                        }
                    )
                if refs:
                    counts["with_refs"] += 1
                counts["entries"] += 1
                if refs or not with_refs_only:
                    value = _read_ptr(memory, addr)
                    results.append(
                        {
                            "address": _format_addr(_s64(addr.getOffset())),
                            "block": blk.getName(),
                            "data_type": data_entry.getDataType().getName() if data_entry else None,
                            "data_value": str(data_entry.getValue()) if data_entry else None,
                            "pointer_value": _format_addr(value) if value is not None else None,
                            "ref_count": len(refs),
                            "callers": callers,
                        }
                    )
                addr = addr.add(8)

        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "scan_all_blocks": scan_all,
            "with_refs_only": with_refs_only,
            "got_block_mode": got_mode,
            "got_blocks": [
                {
                    "name": b.getName(),
                    "start": _format_addr(_s64(b.getStart().getOffset())),
                    "end": _format_addr(_s64(b.getEnd().getOffset())),
                }
                for b in got_blocks
            ],
            "counts": counts,
        }
        with open(os.path.join(out_dir, "got_ref_sweep.json"), "w") as f:
            json.dump({"meta": meta, "entries": results}, f, indent=2, sort_keys=True)
        print("kernel_got_ref_sweep: entries %d (with refs %d)" % (counts["entries"], counts["with_refs"]))
    except Exception:
        if out_dir:
            try:
                _ensure(out_dir)
                with open(os.path.join(out_dir, "error.log"), "w") as err:
                    traceback.print_exc(file=err)
            except Exception:
                pass
        traceback.print_exc()


run()
