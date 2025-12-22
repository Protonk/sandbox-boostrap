#@category Sandbox
"""
Scan for direct BL (and optional B) call sites that target stub/trampoline addresses.

Args: <out_dir> <build_id> stub-targets=<json>|stub-map=<json> [scan_all] [include_b]
  stub-targets: JSON from match_stub_got.py (targets/matches list).
  stub-map: stub_got_map.json to use directly when no stub-targets provided.
  scan_all: include non-executable blocks (default: exec-only).
  include_b: include direct B (tail-call) sites in addition to BL.

Outputs: <out_dir>/stub_call_sites.json
"""

import json
import os
import traceback

from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import Instruction

_RUN_CALLED = False
MASK64 = 0xFFFFFFFFFFFFFFFFL
SIGN_BIT = 0x8000000000000000L


def _u64(val):
    try:
        return long(val) & MASK64
    except Exception:
        return None


def _s64(val):
    try:
        v = long(val) & MASK64
    except Exception:
        return None
    if v & SIGN_BIT:
        return v - (1 << 64)
    return v


def _format_addr(value):
    if value is None:
        return None
    if value < 0:
        return "0x-%x" % abs(value)
    return "0x%x" % value


def _ensure_out_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


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


def _load_json(path):
    with open(path, "r") as fh:
        return json.load(fh)


def _load_stubs(stub_targets_path, stub_map_path):
    source = None
    data = {}
    stubs = []
    if stub_targets_path:
        data = _load_json(stub_targets_path)
        stubs = data.get("targets") or data.get("matches") or []
        source = "stub_targets"
    elif stub_map_path:
        data = _load_json(stub_map_path)
        stubs = data.get("stubs") or []
        source = "stub_map"
    return stubs, data.get("meta", {}), source


def _stub_label(stub):
    name = stub.get("name") or stub.get("got_symbol")
    if name:
        return name
    names = stub.get("stub_symbol_names")
    if isinstance(names, list) and names:
        return ",".join(str(n) for n in names)
    if isinstance(names, str):
        return names
    return None


def _stub_entry_candidates(stub):
    fields = [
        "stub_entry",
        "stub_adrp",
        "adrp",
        "stub_address",
        "address",
        "stub_branch",
        "branch",
    ]
    addrs = []
    for key in fields:
        value = stub.get(key)
        if value is None:
            continue
        try:
            addr = _parse_hex(value)
        except Exception:
            addr = None
        if addr is None:
            continue
        addrs.append(addr)
    return addrs


def _collect_stub_index(stubs):
    index = {}
    for stub in stubs:
        addrs = _stub_entry_candidates(stub)
        if not addrs:
            continue
        entry = {
            "label": _stub_label(stub),
            "got_address": stub.get("got_address"),
            "got_symbol": stub.get("got_symbol"),
            "got_index": stub.get("got_index"),
            "stub_kind": stub.get("stub_kind") or stub.get("kind"),
            "stub_block": stub.get("stub_block"),
            "stub_adrp": stub.get("stub_adrp") or stub.get("adrp"),
            "stub_branch": stub.get("stub_branch") or stub.get("branch"),
            "stub_address": stub.get("stub_address") or stub.get("address"),
        }
        for addr in addrs:
            index.setdefault(addr, []).append(entry)
    return index


def _select_blocks(scan_all):
    mem = currentProgram.getMemory()
    blocks = list(mem.getBlocks())
    if scan_all:
        picked = blocks
    else:
        picked = [blk for blk in blocks if blk.isExecute()]
    return blocks, picked


def _block_set(blocks):
    aset = AddressSet()
    for blk in blocks:
        aset.add(blk.getStart(), blk.getEnd())
    return aset


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print(
                "usage: kernel_stub_call_sites.py <out_dir> <build_id> stub-targets=<json>|stub-map=<json> [scan_all] [include_b]"
            )
            return
        out_dir = args[0]
        build_id = args[1] if len(args) > 1 else ""
        stub_targets_path = None
        stub_map_path = None
        scan_all = False
        include_b = False
        for arg in args[2:]:
            val = str(arg)
            low = val.lower()
            if low.startswith("stub-targets=") or low.startswith("stub_targets="):
                stub_targets_path = val.split("=", 1)[1]
                continue
            if low.startswith("stub-map=") or low.startswith("stub_map="):
                stub_map_path = val.split("=", 1)[1]
                continue
            if low in ("scan_all", "all"):
                scan_all = True
                continue
            if low in ("include_b", "include-b", "b"):
                include_b = True
                continue

        if not stub_targets_path and not stub_map_path:
            print("kernel_stub_call_sites: missing stub-targets or stub-map path")
            return

        stubs, stub_meta, stub_source = _load_stubs(stub_targets_path, stub_map_path)
        stub_index = _collect_stub_index(stubs)
        stub_addrs = set(stub_index.keys())

        _ensure_out_dir(out_dir)
        all_blocks, picked = _select_blocks(scan_all)
        addr_set = _block_set(picked)
        listing = currentProgram.getListing()
        func_mgr = currentProgram.getFunctionManager()
        memory = currentProgram.getMemory()
        call_sites = []
        seen = set()

        instr_iter = listing.getInstructions(addr_set, True)
        while instr_iter.hasNext() and not monitor.isCancelled():
            instr = instr_iter.next()
            if not isinstance(instr, Instruction):
                continue
            mnemonic = instr.getMnemonicString().upper()
            if mnemonic == "BL":
                pass
            elif include_b and mnemonic == "B":
                pass
            else:
                continue
            flows = instr.getFlows()
            if not flows:
                continue
            target = flows[0]
            target_off = _s64(target.getOffset())
            if target_off not in stub_addrs:
                continue
            key = (instr.getAddress().getOffset(), target_off, mnemonic)
            if key in seen:
                continue
            seen.add(key)
            func = func_mgr.getFunctionContaining(instr.getAddress())
            block = memory.getBlock(instr.getAddress())
            stub_entries = stub_index.get(target_off, [])
            call_sites.append(
                {
                    "call_address": _format_addr(_s64(instr.getAddress().getOffset())),
                    "call_mnemonic": mnemonic,
                    "target_address": _format_addr(target_off),
                    "function": {
                        "name": func.getName() if func else None,
                        "entry": _format_addr(_s64(func.getEntryPoint().getOffset())) if func else None,
                        "size": func.getBody().getNumAddresses() if func else None,
                    },
                    "block": block.getName() if block else None,
                    "stub_entries": stub_entries,
                }
            )

        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "stub_source": stub_source,
            "stub_target_path": stub_targets_path,
            "stub_map_path": stub_map_path,
            "stub_entry_count": len(stub_addrs),
            "stub_record_count": len(stubs),
            "call_site_count": len(call_sites),
            "scan_all_blocks": scan_all,
            "include_b": include_b,
            "block_filter": [
                {
                    "name": b.getName(),
                    "start": _format_addr(_s64(b.getStart().getOffset())),
                    "end": _format_addr(_s64(b.getEnd().getOffset())),
                }
                for b in picked
            ],
            "all_block_names": sorted(set((b.getName() or "") for b in all_blocks)),
            "stub_meta": stub_meta,
        }
        with open(os.path.join(out_dir, "stub_call_sites.json"), "w") as fh:
            json.dump({"meta": meta, "call_sites": call_sites}, fh, indent=2, sort_keys=True)
        print("kernel_stub_call_sites: %d call sites" % len(call_sites))
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
