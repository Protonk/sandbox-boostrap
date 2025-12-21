#@category Sandbox
"""
Locate mac_policy_register call sites (or mac_policy* symbols) and attempt to
recover argument pointers for static registration-site recovery.

Args: <out_dir> [build_id] [query substrings...]
Flags:
  flow | scan-flows          scan call flows in addition to references
  indirect | scan-indirect   scan BLR/BLRAA call sites via __auth_got
  indirect-all               include all indirect call sites (ignore query filter)
  all | scan-all             scan all blocks (skip sandbox-only filtering)
Defaults:
  query substrings = ["mac_policy_register", "mac_policy"]

Outputs:
  registration_sites.json (call sites + arg recovery attempts)
"""

import json
import os
import traceback

from ghidra.program.model.address import Address, AddressSet
from ghidra.program.model.lang import Register
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.scalar import Scalar

MASK64 = 0xFFFFFFFFFFFFFFFFL
_RUN = False


def _ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _u64(val):
    try:
        return long(val) & MASK64
    except Exception:
        return None


def _normalize_reg(name):
    if not name:
        return None
    name = name.lower()
    if name.startswith("w") and name[1:].isdigit():
        return "x" + name[1:]
    return name


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


def _find_got_blocks():
    mem = currentProgram.getMemory()
    blocks = []
    for blk in mem.getBlocks():
        name = (blk.getName() or "").lower()
        if "auth_got" in name:
            blocks.append(blk)
    if blocks:
        return blocks, "auth_got"
    fallback = []
    for blk in mem.getBlocks():
        name = (blk.getName() or "").lower()
        if "got" in name:
            fallback.append(blk)
    return fallback, "got"


def _first_address_operand(instr):
    for i in range(instr.getNumOperands()):
        for obj in instr.getOpObjects(i):
            if isinstance(obj, Address):
                return obj.getOffset()
    return None


def _first_scalar_operand(instr):
    for i in range(instr.getNumOperands()):
        for obj in instr.getOpObjects(i):
            if isinstance(obj, Scalar):
                return _u64(obj.getValue())
    return None


def _first_register_operand(instr, op_index=None):
    if op_index is not None and op_index < instr.getNumOperands():
        ops = instr.getOpObjects(op_index)
        for obj in ops:
            if isinstance(obj, Register):
                return obj.getName()
        return None
    for i in range(instr.getNumOperands()):
        for obj in instr.getOpObjects(i):
            if isinstance(obj, Register):
                return obj.getName()
    return None


def _parse_mem_operand(instr):
    if instr.getNumOperands() < 2:
        return None, None
    base_reg = None
    offset = None
    for obj in instr.getOpObjects(1):
        if isinstance(obj, Register) and base_reg is None:
            base_reg = obj.getName()
        elif isinstance(obj, Scalar) and offset is None:
            offset = _u64(obj.getValue())
    return base_reg, offset


def _call_target_register(instr):
    return _first_register_operand(instr, 0)


def _writes_reg(instr, reg_name):
    try:
        results = instr.getResultObjects()
    except Exception:
        results = []
    for obj in results or []:
        if isinstance(obj, Register):
            if _normalize_reg(obj.getName()) == reg_name:
                return True
    return False


def _read_ptr(memory, addr):
    if addr is None or addr == 0:
        return None
    try:
        return _u64(memory.getLong(toAddr(addr)))
    except (MemoryAccessException, Exception):
        return None


def _result_value(value, source, instr=None):
    out = {"value": "0x%x" % value, "source": source, "_value_int": value}
    if instr is not None:
        out["instruction"] = instr.toString()
    return out


def _resolve_reg_value(start_instr, reg_name, memory, max_back=40, depth=2):
    instr = start_instr
    steps = 0
    pending = None
    while instr and steps < max_back and not monitor.isCancelled():
        if not _writes_reg(instr, reg_name):
            instr = instr.getPrevious()
            steps += 1
            continue
        mnemonic = instr.getMnemonicString().upper()
        if mnemonic in ("ADRP", "ADR"):
            base = _first_address_operand(instr)
            if base is None:
                return {"value": None, "source": "adrp_no_addr", "instruction": instr.toString()}
            if pending:
                value = _u64(base + pending["delta"])
                if pending["kind"] == "ldr":
                    loaded = _read_ptr(memory, value)
                    res = _result_value(value, "%s+ldr" % mnemonic.lower(), instr)
                    res["mem_addr"] = "0x%x" % value
                    if loaded is not None:
                        res["loaded_value"] = "0x%x" % loaded
                    return res
                return _result_value(value, "%s+%s" % (mnemonic.lower(), pending["kind"]), instr)
            return _result_value(_u64(base), mnemonic.lower(), instr)
        if mnemonic in ("ADD", "SUB"):
            src_reg = _first_register_operand(instr, 1)
            scalar = _first_scalar_operand(instr)
            if scalar is not None and src_reg:
                sign = 1 if mnemonic == "ADD" else -1
                src_norm = _normalize_reg(src_reg)
                if src_norm == reg_name:
                    pending = {"kind": "add", "delta": sign * scalar}
                    instr = instr.getPrevious()
                    steps += 1
                    continue
                if depth > 0:
                    base_val = _resolve_reg_value(instr.getPrevious(), src_norm, memory, max_back, depth - 1)
                    base_int = base_val.get("_value_int") if base_val else None
                    if base_int is not None:
                        value = _u64(base_int + sign * scalar)
                        res = _result_value(value, "%s+%s" % (base_val.get("source"), mnemonic.lower()), instr)
                        return res
        if mnemonic.startswith("LDR") or mnemonic.startswith("LDRA") or mnemonic.startswith("LDUR"):
            base_reg, offset = _parse_mem_operand(instr)
            offset = offset or 0
            if base_reg:
                base_norm = _normalize_reg(base_reg)
                if base_norm == reg_name:
                    pending = {"kind": "ldr", "delta": offset}
                    instr = instr.getPrevious()
                    steps += 1
                    continue
                if depth > 0:
                    base_val = _resolve_reg_value(instr.getPrevious(), base_norm, memory, max_back, depth - 1)
                    base_int = base_val.get("_value_int") if base_val else None
                    if base_int is not None:
                        mem_addr = _u64(base_int + offset)
                        loaded = _read_ptr(memory, mem_addr)
                        res = _result_value(mem_addr, "base+ldr", instr)
                        res["mem_addr"] = "0x%x" % mem_addr
                        if loaded is not None:
                            res["loaded_value"] = "0x%x" % loaded
                        res["base_reg"] = base_norm
                        res["base_source"] = base_val.get("source")
                        return res
            addr = _first_address_operand(instr)
            if addr is not None:
                mem_addr = _u64(addr)
                loaded = _read_ptr(memory, mem_addr)
                res = _result_value(mem_addr, "ldr_literal", instr)
                res["mem_addr"] = "0x%x" % mem_addr
                if loaded is not None:
                    res["loaded_value"] = "0x%x" % loaded
                return res
        if mnemonic in ("MOV", "MOVZ", "MOVK"):
            scalar = _first_scalar_operand(instr)
            if scalar is not None:
                return _result_value(_u64(scalar), mnemonic.lower(), instr)
            src_reg = _first_register_operand(instr, 1)
            if src_reg:
                return {"value": None, "source": "mov:%s" % _normalize_reg(src_reg), "instruction": instr.toString()}
        return {"value": None, "source": mnemonic.lower(), "instruction": instr.toString()}
    return {"value": None, "source": "unresolved", "scan_limit": max_back}


def _clean_result(result, memory):
    if not result:
        return {"value": None, "source": "unresolved"}
    result = dict(result)
    value_int = result.pop("_value_int", None)
    if value_int is not None:
        try:
            block = memory.getBlock(toAddr(value_int))
            result["value_block"] = block.getName() if block else None
        except Exception:
            result["value_block"] = None
    return result


def _addr_in_blocks(addr, blocks):
    try:
        a = toAddr(addr)
    except Exception:
        return None
    for blk in blocks:
        if blk.contains(a):
            return blk
    return None


def _symbols_at_address(symtab, addr):
    names = []
    libs = []
    try:
        sym_iter = symtab.getSymbols(toAddr(addr))
    except Exception:
        sym_iter = []
    for sym in sym_iter:
        name = sym.getName() or ""
        if name and name not in names:
            names.append(name)
        try:
            loc = sym.getExternalLocation()
        except Exception:
            loc = None
        if loc and loc.getLibraryName():
            lib = loc.getLibraryName()
            if lib not in libs:
                libs.append(lib)
    return names, libs


def _dump_got_entries(blocks, symtab, memory):
    entries = []
    for blk in blocks:
        start = blk.getStart().getOffset()
        end = blk.getEnd().getOffset()
        limit = end - 7
        addr = start
        while addr <= limit and not monitor.isCancelled():
            names, libs = _symbols_at_address(symtab, addr)
            entry = {
                "address": "0x%x" % addr,
                "block": blk.getName(),
                "symbol_names": names,
                "symbol_libraries": libs,
            }
            val = _read_ptr(memory, addr)
            if val is not None:
                entry["pointer_value"] = "0x%x" % val
            entries.append(entry)
            addr += 8
    return entries


def _collect_target_symbols(substrings):
    symtab = currentProgram.getSymbolTable()
    memory = currentProgram.getMemory()
    targets = []
    seen = set()

    def _maybe_add(sym, external_loc=None, external=False):
        name = sym.getName() or ""
        lname = name.lower()
        if not any(sub in lname for sub in substrings):
            return
        addr = sym.getAddress()
        key = (name, addr.getOffset())
        if key in seen:
            return
        seen.add(key)
        block = memory.getBlock(addr)
        entry = {
            "name": name,
            "address": "0x%x" % addr.getOffset(),
            "_address_offset": addr.getOffset(),
            "symbol_type": sym.getSymbolType().toString(),
            "external": external,
            "block": block.getName() if block else None,
        }
        if external_loc:
            entry["library"] = external_loc.getLibraryName()
        targets.append(entry)

    ext_iter = symtab.getExternalSymbols()
    while ext_iter.hasNext() and not monitor.isCancelled():
        sym = ext_iter.next()
        loc = None
        try:
            loc = sym.getExternalLocation()
        except Exception:
            loc = None
        _maybe_add(sym, external_loc=loc, external=True)

    sym_iter = symtab.getSymbolIterator(True)
    while sym_iter.hasNext() and not monitor.isCancelled():
        sym = sym_iter.next()
        _maybe_add(sym, external_loc=None, external=False)

    return targets


def _collect_call_sites(targets, max_back, depth, flow_scan, addr_set):
    memory = currentProgram.getMemory()
    ref_mgr = currentProgram.getReferenceManager()
    func_mgr = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    call_sites = []
    seen = set()
    flow_hits = 0

    target_map = {}
    for target in targets:
        off = target.get("_address_offset")
        if off is None:
            continue
        target_map.setdefault(off, []).append(target)

    for target in targets:
        addr = toAddr(long(target["_address_offset"]))
        for ref in ref_mgr.getReferencesTo(addr):
            rtype = ref.getReferenceType()
            if not rtype.isCall():
                continue
            call_addr = ref.getFromAddress()
            if addr_set and not addr_set.contains(call_addr):
                continue
            key = (call_addr.getOffset(), target["name"])
            if key in seen:
                continue
            seen.add(key)
            func = func_mgr.getFunctionContaining(call_addr)
            block = memory.getBlock(call_addr)
            call_instr = listing.getInstructionAt(call_addr)
            args = {}
            if call_instr:
                for reg in ("x0", "x1", "x2"):
                    res = _resolve_reg_value(call_instr.getPrevious(), reg, memory, max_back=max_back, depth=depth)
                    args[reg] = _clean_result(res, memory)
            call_sites.append(
                {
                    "call_address": "0x%x" % call_addr.getOffset(),
                    "target_name": target["name"],
                    "target_address": target["address"],
                    "target_library": target.get("library"),
                    "reference_type": rtype.getName(),
                    "function": {
                        "name": func.getName() if func else None,
                        "entry": "0x%x" % func.getEntryPoint().getOffset() if func else None,
                        "size": func.getBody().getNumAddresses() if func else None,
                    },
                    "block": block.getName() if block else None,
                    "args": args,
                }
            )

    if flow_scan and target_map:
        instr_iter = listing.getInstructions(addr_set, True) if addr_set else listing.getInstructions(True)
        while instr_iter.hasNext() and not monitor.isCancelled():
            instr = instr_iter.next()
            ftype = instr.getFlowType()
            if not ftype or not ftype.isCall():
                continue
            flows = instr.getFlows()
            if not flows:
                continue
            for flow in flows:
                off = flow.getOffset()
                if off not in target_map:
                    continue
                for target in target_map[off]:
                    key = (instr.getAddress().getOffset(), target["name"], "flow")
                    if key in seen:
                        continue
                    seen.add(key)
                    func = func_mgr.getFunctionContaining(instr.getAddress())
                    block = memory.getBlock(instr.getAddress())
                    args = {}
                    for reg in ("x0", "x1", "x2"):
                        res = _resolve_reg_value(instr.getPrevious(), reg, memory, max_back=max_back, depth=depth)
                        args[reg] = _clean_result(res, memory)
                    call_sites.append(
                        {
                            "call_address": "0x%x" % instr.getAddress().getOffset(),
                            "target_name": target["name"],
                            "target_address": target["address"],
                            "target_library": target.get("library"),
                            "reference_type": "flow",
                            "function": {
                                "name": func.getName() if func else None,
                                "entry": "0x%x" % func.getEntryPoint().getOffset() if func else None,
                                "size": func.getBody().getNumAddresses() if func else None,
                            },
                            "block": block.getName() if block else None,
                            "args": args,
                        }
                    )
                    flow_hits += 1
    return call_sites, flow_hits


def _collect_indirect_calls(addr_set, got_blocks, substrings, max_back, depth, include_all):
    memory = currentProgram.getMemory()
    symtab = currentProgram.getSymbolTable()
    func_mgr = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    call_sites = []
    seen = set()
    if not got_blocks:
        return call_sites

    instr_iter = listing.getInstructions(addr_set, True) if addr_set else listing.getInstructions(True)
    while instr_iter.hasNext() and not monitor.isCancelled():
        instr = instr_iter.next()
        ftype = instr.getFlowType()
        if not ftype or not ftype.isCall():
            continue
        mnemonic = instr.getMnemonicString().upper()
        if mnemonic == "BL":
            continue
        if not mnemonic.startswith("BLR"):
            continue
        target_reg = _call_target_register(instr)
        if not target_reg:
            continue
        raw = _resolve_reg_value(instr.getPrevious(), _normalize_reg(target_reg), memory, max_back=max_back, depth=depth)
        mem_addr = raw.get("_value_int") if raw else None
        if mem_addr is None:
            continue
        block = _addr_in_blocks(mem_addr, got_blocks)
        if not block:
            continue
        names, libs = _symbols_at_address(symtab, mem_addr)
        matched = any(sub in name.lower() for name in names for sub in substrings) if substrings else True
        if not include_all and substrings and not matched:
            continue
        key = (instr.getAddress().getOffset(), mem_addr)
        if key in seen:
            continue
        seen.add(key)
        func = func_mgr.getFunctionContaining(instr.getAddress())
        call_block = memory.getBlock(instr.getAddress())
        call_sites.append(
            {
                "call_address": "0x%x" % instr.getAddress().getOffset(),
                "call_mnemonic": mnemonic,
                "function": {
                    "name": func.getName() if func else None,
                    "entry": "0x%x" % func.getEntryPoint().getOffset() if func else None,
                    "size": func.getBody().getNumAddresses() if func else None,
                },
                "block": call_block.getName() if call_block else None,
                "got_address": "0x%x" % mem_addr,
                "got_block": block.getName(),
                "got_symbols": names,
                "got_libraries": libs,
                "matched_query": matched,
                "arg_x0": _clean_result(_resolve_reg_value(instr.getPrevious(), "x0", memory, max_back=max_back, depth=depth), memory),
                "arg_x1": _clean_result(_resolve_reg_value(instr.getPrevious(), "x1", memory, max_back=max_back, depth=depth), memory),
                "arg_x2": _clean_result(_resolve_reg_value(instr.getPrevious(), "x2", memory, max_back=max_back, depth=depth), memory),
            }
        )
    return call_sites


def run():
    global _RUN
    if _RUN:
        return
    _RUN = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 1:
            print("usage: mac_policy_register_scan.py <out_dir> [build_id] [query substrings...]")
            return
        out_dir = args[0]
        build_id = args[1] if len(args) > 1 else ""
        substrings = []
        flow_scan = False
        indirect_scan = False
        indirect_all = False
        scan_all = False
        for item in args[2:]:
            val = item.lower()
            if val in ("flow", "scan-flows"):
                flow_scan = True
                continue
            if val in ("indirect", "scan-indirect"):
                indirect_scan = True
                continue
            if val in ("indirect-all", "scan-indirect-all"):
                indirect_scan = True
                indirect_all = True
                continue
            if val in ("all", "scan-all"):
                scan_all = True
                continue
            substrings.append(val)
        if not substrings:
            substrings = ["mac_policy_register", "mac_policy"]

        _ensure_dir(out_dir)
        trace_path = os.path.join(out_dir, "trace.log")
        with open(trace_path, "a") as trace:
            trace.write("start\n")

        blocks = list(currentProgram.getMemory().getBlocks()) if scan_all else _sandbox_blocks()
        addr_set = _block_set(blocks)

        targets = _collect_target_symbols(substrings)
        call_sites, flow_hits = _collect_call_sites(targets, max_back=40, depth=2, flow_scan=flow_scan, addr_set=addr_set)
        clean_targets = []
        for target in targets:
            target = dict(target)
            target.pop("_address_offset", None)
            clean_targets.append(target)
        got_blocks, got_mode = _find_got_blocks()
        indirect_sites = []
        got_entries = []
        if indirect_scan and got_blocks:
            indirect_sites = _collect_indirect_calls(
                addr_set, got_blocks, substrings, max_back=40, depth=2, include_all=indirect_all
            )
            got_entries = _dump_got_entries(got_blocks, currentProgram.getSymbolTable(), currentProgram.getMemory())
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "query_substrings": substrings,
            "target_count": len(targets),
            "call_site_count": len(call_sites),
            "flow_scan": flow_scan,
            "flow_call_sites": flow_hits,
            "indirect_scan": indirect_scan,
            "indirect_all": indirect_all,
            "indirect_call_sites": len(indirect_sites),
            "scan_all_blocks": scan_all,
            "got_block_mode": got_mode if got_blocks else None,
            "scan_limits": {"max_back": 40, "depth": 2},
        }

        with open(os.path.join(out_dir, "registration_sites.json"), "w") as f:
            json.dump(
                {
                    "meta": meta,
                    "targets": clean_targets,
                    "call_sites": call_sites,
                    "indirect_call_sites": indirect_sites,
                    "got_blocks": [
                        {
                            "name": b.getName(),
                            "start": "0x%x" % b.getStart().getOffset(),
                            "end": "0x%x" % b.getEnd().getOffset(),
                        }
                        for b in got_blocks
                    ],
                    "got_entries": got_entries,
                },
                f,
                indent=2,
                sort_keys=True,
            )
        print("mac_policy_register_scan: wrote %d call sites to %s" % (len(call_sites), out_dir))
        with open(trace_path, "a") as trace:
            trace.write("done\n")
    except Exception:
        if out_dir:
            try:
                _ensure_dir(out_dir)
                with open(os.path.join(out_dir, "error.log"), "w") as err:
                    traceback.print_exc(file=err)
            except Exception:
                pass
        traceback.print_exc()


if not os.environ.get("GHIDRA_SKIP_AUTORUN"):
    run()
