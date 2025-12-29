#@category Sandbox
"""
Dump jump-table entries for dispatcher-like functions that use ADRP+ADD+LDRSW+ADR+ADD+BR patterns.

Args (from scaffold/manual): <out_dir> <build_id> <function_or_addr> [max_back] [max_entries]
  function_or_addr: function name (e.g., FUN_fffffe...) or addr:<hex>.
  max_back: instruction lookback window (default: 14).
  max_entries: limit table entries read (default: 512).

Outputs: <out_dir>/jump_tables.json
"""

import json
import os
import re
import traceback

from ghidra_bootstrap import scan_utils

from ghidra.program.model.address import Address

_RUN_CALLED = False

BR_RE = re.compile(r"^(br|braa|brab)\s+(\w+)(?:\s*,\s*(\w+))?$")
LDRSW_RE = re.compile(r"^ldrsw\s+(\w+)\s*,\s*\[(\w+)\s*,\s*(\w+)\s*,\s*lsl\s*#0x2\]$")
ADRP_RE = re.compile(r"^adrp\s+(\w+)\s*,\s*([-0-9xa-f]+)$")
ADD_IMM_RE = re.compile(r"^add\s+(\w+)\s*,\s*(\w+)\s*,\s*#([0-9xa-f]+)$")
ADR_RE = re.compile(r"^adr\s+(\w+)\s*,\s*([-0-9xa-f]+)$")
SUB_IMM_RE = re.compile(r"^subs?\s+(\w+)\s*,\s*(\w+)\s*,\s*#([0-9xa-f]+)$")
CMP_IMM_RE = re.compile(r"^cmp\s+(\w+)\s*,\s*#([0-9xa-f]+)$")


def _ensure_out_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _parse_int(token, default=None):
    try:
        return int(token, 0)
    except Exception:
        return default


def _parse_signed_hex(token):
    return scan_utils.parse_signed_hex(token)


def _to_u64(value):
    return scan_utils.to_unsigned(value)


def _hex_u64(value):
    return scan_utils.format_address(value)


def _find_function_by_name(name):
    func_mgr = currentProgram.getFunctionManager()
    func_iter = func_mgr.getFunctions(True)
    while func_iter.hasNext() and not monitor.isCancelled():
        func = func_iter.next()
        if func.getName() == name:
            return func
    return None


def _reg_key(reg):
    reg = reg.lower()
    if reg.startswith("x") or reg.startswith("w"):
        return reg[1:]
    return reg


def _resolve_target(token):
    func_mgr = currentProgram.getFunctionManager()
    addr_factory = currentProgram.getAddressFactory()
    addr_space = addr_factory.getDefaultAddressSpace()
    if token.startswith("addr:"):
        raw = token.split("addr:", 1)[1]
        addr_val = _parse_signed_hex(raw)
        if addr_val is None:
            return None
        addr_val = _to_u64(addr_val)
        addr = addr_space.getAddress(scan_utils.format_address(addr_val))
        return func_mgr.getFunctionContaining(addr)
    func = _find_function_by_name(token)
    if func:
        return func
    raw = _parse_signed_hex(token)
    if raw is None:
        return None
    addr_val = _to_u64(raw)
    addr = addr_space.getAddress(scan_utils.format_address(addr_val))
    return func_mgr.getFunctionContaining(addr)


def _choose_adrp_page(instr_addr, imm_signed, memory):
    if imm_signed is None:
        return None
    inst_page = instr_addr & ~0xFFF
    candidates = []
    candidates.append(inst_page + imm_signed)
    candidates.append(inst_page + (imm_signed << 12))
    if abs(imm_signed) > 0x100000:
        candidates.append(imm_signed & ~0xFFF)
    addr_factory = currentProgram.getAddressFactory()
    addr_space = addr_factory.getDefaultAddressSpace()
    for cand in candidates:
        cand_u = _to_u64(cand)
        try:
            addr = addr_space.getAddress(scan_utils.format_address(cand_u))
            if memory.getBlock(addr):
                return cand_u
        except Exception:
            continue
    return None


def _resolve_adr_target(instr_addr, imm_signed):
    if imm_signed is None:
        return None
    if abs(imm_signed) < 0x100000:
        return _to_u64(instr_addr + imm_signed)
    return _to_u64(imm_signed)


def _scan_jump_tables(func, max_back, max_entries):
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
    func_mgr = currentProgram.getFunctionManager()
    addr_factory = currentProgram.getAddressFactory()
    addr_space = addr_factory.getDefaultAddressSpace()

    insts = []
    inst_iter = listing.getInstructions(func.getBody(), True)
    while inst_iter.hasNext() and not monitor.isCancelled():
        insts.append(inst_iter.next())

    tables = []
    for idx, inst in enumerate(insts):
        text = inst.toString().strip().lower()
        br_match = BR_RE.match(text)
        if not br_match:
            continue
        br_reg = br_match.group(2)
        br_key = _reg_key(br_reg)
        br_addr = inst.getAddress().getOffset()
        window_start = max(0, idx - max_back)
        window = insts[window_start:idx]

        ldr_info = None
        for back in reversed(window):
            m = LDRSW_RE.match(back.toString().strip().lower())
            if not m:
                continue
            dest, base, index = m.group(1), m.group(2), m.group(3)
            if _reg_key(dest) != br_key:
                continue
            ldr_info = {"dest": dest, "base": base, "index": index, "addr": back.getAddress().getOffset()}
            break
        if not ldr_info:
            continue

        table_add = None
        table_add_addr = None
        table_page = None
        table_adrp_addr = None
        for back in reversed(window):
            t = back.toString().strip().lower()
            m = ADD_IMM_RE.match(t)
            if m and m.group(1) == ldr_info["base"] and m.group(2) == ldr_info["base"]:
                table_add = _parse_int(m.group(3))
                table_add_addr = back.getAddress().getOffset()
                break
        for back in reversed(window):
            t = back.toString().strip().lower()
            m = ADRP_RE.match(t)
            if m and m.group(1) == ldr_info["base"]:
                imm_signed = _parse_signed_hex(m.group(2))
                table_page = _choose_adrp_page(back.getAddress().getOffset(), imm_signed, memory)
                table_adrp_addr = back.getAddress().getOffset()
                break

        target_base = None
        target_base_reg = None
        target_adr_addr = None
        for back in reversed(window):
            t = back.toString().strip().lower()
            m = ADR_RE.match(t)
            if not m:
                continue
            target_base_reg = m.group(1)
            imm_signed = _parse_signed_hex(m.group(2))
            target_base = _resolve_adr_target(back.getAddress().getOffset(), imm_signed)
            target_adr_addr = back.getAddress().getOffset()
            break

        index_base = None
        index_src = None
        index_cmp = None
        index_cmp_reg = None
        source_cmp = None
        source_cmp_reg = None
        index_key = _reg_key(ldr_info["index"])
        for back in reversed(window):
            t = back.toString().strip().lower()
            m = SUB_IMM_RE.match(t)
            if m and _reg_key(m.group(1)) == index_key:
                index_src = m.group(2)
                index_base = _parse_int(m.group(3))
                break
        for back in reversed(window):
            t = back.toString().strip().lower()
            m = CMP_IMM_RE.match(t)
            if not m:
                continue
            reg = m.group(1)
            imm = _parse_int(m.group(2))
            if _reg_key(reg) == index_key and index_cmp is None:
                index_cmp = imm
                index_cmp_reg = reg
            if index_src and _reg_key(reg) == _reg_key(index_src) and source_cmp is None:
                source_cmp = imm
                source_cmp_reg = reg

        entry_limit = max_entries
        entry_count = None
        if index_cmp is not None:
            entry_count = index_cmp + 1
            entry_limit = min(entry_limit, entry_count)

        table_addr = None
        if table_page is not None and table_add is not None:
            table_addr = _to_u64(table_page + table_add)

        entries = []
        table_block = None
        if table_addr is not None:
            try:
                table_addr_obj = addr_space.getAddress(scan_utils.format_address(table_addr))
                table_block = memory.getBlock(table_addr_obj)
            except Exception:
                table_block = None
        if table_addr is not None and table_block is not None:
            for i in range(entry_limit):
                try:
                    ent_addr = table_addr + (i * 4)
                    ent_addr_obj = addr_space.getAddress(scan_utils.format_address(ent_addr))
                    offset = memory.getInt(ent_addr_obj)
                    offset_val = int(offset)
                    target = None
                    target_block = None
                    target_func = None
                    if target_base is not None:
                        target = _to_u64(target_base + offset_val)
                        try:
                            tgt_addr = addr_space.getAddress(scan_utils.format_address(target))
                            target_block = memory.getBlock(tgt_addr)
                            func = func_mgr.getFunctionContaining(tgt_addr)
                            target_func = func.getName() if func else None
                        except Exception:
                            target_block = None
                    entries.append(
                        {
                            "index": i,
                            "entry_addr": _hex_u64(ent_addr),
                            "offset": offset_val,
                            "target": _hex_u64(target),
                            "target_block": target_block.getName() if target_block else None,
                            "target_function": target_func,
                        }
                    )
                except Exception:
                    break

        tables.append(
            {
                "br_addr": _hex_u64(br_addr),
                "br_reg": br_reg,
                "ldrsw_addr": _hex_u64(ldr_info["addr"]),
                "index_reg": ldr_info["index"],
                "table_reg": ldr_info["base"],
                "table_adrp_addr": _hex_u64(table_adrp_addr),
                "table_add_addr": _hex_u64(table_add_addr),
                "table_page": _hex_u64(table_page),
                "table_add": _hex_u64(table_add) if table_add is not None else None,
                "table_addr": _hex_u64(table_addr),
                "table_block": table_block.getName() if table_block else None,
                "target_adr_addr": _hex_u64(target_adr_addr),
                "target_base": _hex_u64(target_base),
                "index_base": index_base,
                "index_cmp": index_cmp,
                "index_cmp_reg": index_cmp_reg,
                "source_cmp": source_cmp,
                "source_cmp_reg": source_cmp_reg,
                "entry_count": entry_count,
                "entries": entries,
            }
        )
    return tables


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_jump_table_dump.py <out_dir> <build_id> <function_or_addr> [max_back] [max_entries]")
            return
        out_dir = args[0]
        build_id = args[1]
        target = args[2]
        max_back = _parse_int(args[3], 14) if len(args) > 3 else 14
        max_entries = _parse_int(args[4], 512) if len(args) > 4 else 512

        _ensure_out_dir(out_dir)
        func = _resolve_target(target)
        if not func:
            raise ValueError("Target function not found: %s" % target)

        tables = _scan_jump_tables(func, max_back, max_entries)
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "target": target,
            "function": func.getName(),
            "function_entry": _hex_u64(func.getEntryPoint().getOffset()),
            "max_back": max_back,
            "max_entries": max_entries,
            "table_count": len(tables),
        }
        with open(os.path.join(out_dir, "jump_tables.json"), "w") as fh:
            json.dump({"meta": meta, "tables": tables}, fh, indent=2, sort_keys=True)
        print("kernel_jump_table_dump: wrote %d tables" % len(tables))
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
