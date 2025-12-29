#@category Sandbox
"""
Scan executable code for GOT loads or direct refs into __auth_got/__got/__auth_ptr.

Args: <out_dir> <build_id> [lookback] [all] [refs_only] [target_only=addr1,addr2]
  lookback: instruction backtrack depth for base-reg resolution (default: 16).
  all: scan all blocks (default: sandbox-only, fallback to all).
  refs_only: only record direct references (skip backtracking).
  target_only: comma-separated list of GOT entry addresses to include.

Outputs: <out_dir>/got_load_sweep.json

Notes:
- __auth_got and __auth_ptr store pointer-authenticated entries; treat them as distinct from plain __got.
- Lookback depth trades accuracy for speed; larger values chase more register defs.
"""

import json
import os
import traceback

from ghidra_bootstrap import block_utils, scan_utils

from ghidra.program.model.address import Address, AddressSet
from ghidra.program.model.lang import Register
from ghidra.program.model.listing import Instruction
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.scalar import Scalar

_RUN = False


def _ensure(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _s64(val):
    return scan_utils.to_signed(val)


def _format_addr(value):
    return scan_utils.format_signed_hex(value)


def _parse_hex_address(text):
    return scan_utils.parse_signed_hex(text)


def _sandbox_blocks():
    return block_utils.sandbox_blocks(program=currentProgram)

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
    # Collapse block kinds into a single mode label for metadata.
    mode = "+".join(sorted(set(kinds))) if kinds else None
    return got_blocks, mode


def _exec_blocks(blocks):
    exec_blocks = [b for b in blocks if b.isExecute()]
    if exec_blocks:
        return exec_blocks
    # If none are marked executable, fall back to all blocks to avoid empty scans.
    return blocks


def _block_set(blocks):
    return block_utils.block_set(blocks)

def _addr_in_blocks(addr, blocks):
    try:
        a = toAddr(_s64(addr))
    except Exception:
        return None
    for blk in blocks:
        if blk.contains(a):
            return blk
    return None


def _scalar_val(obj):
    if isinstance(obj, Scalar):
        try:
            return obj.getUnsignedValue()
        except Exception:
            try:
                return obj.getValue()
            except Exception:
                return None
    return None


def _normalize_reg(name):
    if not name:
        return None
    name = name.lower()
    # Normalize wN to xN so register matches are width-agnostic.
    if name.startswith("w") and name[1:].isdigit():
        return "x" + name[1:]
    return name


def _first_address_operand(instr):
    for i in range(instr.getNumOperands()):
        for obj in instr.getOpObjects(i):
            if isinstance(obj, Address):
                return _s64(obj.getOffset())
    return None


def _first_scalar_operand(instr):
    for i in range(instr.getNumOperands()):
        for obj in instr.getOpObjects(i):
            if isinstance(obj, Scalar):
                return _scalar_val(obj)
    return None


def _first_register_operand(instr, op_index=None):
    if op_index is not None and op_index < instr.getNumOperands():
        for obj in instr.getOpObjects(op_index):
            if isinstance(obj, Register):
                return _normalize_reg(obj.getName())
        return None
    for i in range(instr.getNumOperands()):
        for obj in instr.getOpObjects(i):
            if isinstance(obj, Register):
                return _normalize_reg(obj.getName())
    return None


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


def _parse_mem_operand(instr):
    if instr.getNumOperands() < 2:
        return None, None
    base_reg = None
    offset = None
    for obj in instr.getOpObjects(1):
        if isinstance(obj, Register) and base_reg is None:
            base_reg = _normalize_reg(obj.getName())
        elif isinstance(obj, Scalar) and offset is None:
            offset = _scalar_val(obj)
    return base_reg, offset or 0


def _is_ldr(instr):
    m = instr.getMnemonicString().upper()
    return m.startswith("LDR") or m.startswith("LDRA") or m.startswith("LDUR")


def _read_ptr(memory, addr):
    if addr is None or addr == 0:
        return None
    try:
        return _s64(memory.getLong(toAddr(_s64(addr))))
    except (MemoryAccessException, Exception):
        return None


def _resolve_reg_value(start_instr, reg_name, memory, max_back=16, depth=2):
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
                value = _s64(base + pending["delta"])
                if pending["kind"] == "ldr":
                    loaded = _read_ptr(memory, value)
                    return {
                        "value": value,
                        "source": "%s+ldr" % mnemonic.lower(),
                        "instruction": instr.toString(),
                        "mem_addr": value,
                        "loaded_value": loaded,
                    }
                return {"value": value, "source": "%s+%s" % (mnemonic.lower(), pending["kind"]), "instruction": instr.toString()}
            return {"value": base, "source": mnemonic.lower(), "instruction": instr.toString()}
        if mnemonic in ("ADD", "SUB"):
            src_reg = _first_register_operand(instr, 1)
            scalar = _first_scalar_operand(instr)
            if scalar is not None and src_reg:
                sign = 1 if mnemonic == "ADD" else -1
                if src_reg == reg_name:
                    pending = {"kind": "add", "delta": sign * scalar}
                    instr = instr.getPrevious()
                    steps += 1
                    continue
                if depth > 0:
                    base_val = _resolve_reg_value(instr.getPrevious(), src_reg, memory, max_back, depth - 1)
                    base_int = base_val.get("value") if base_val else None
                    if base_int is not None:
                        value = _s64(base_int + sign * scalar)
                        return {"value": value, "source": "%s+%s" % (base_val.get("source"), mnemonic.lower()), "instruction": instr.toString()}
        if mnemonic.startswith("LDR") or mnemonic.startswith("LDRA") or mnemonic.startswith("LDUR"):
            base_reg, offset = _parse_mem_operand(instr)
            if base_reg:
                if base_reg == reg_name:
                    pending = {"kind": "ldr", "delta": offset}
                    instr = instr.getPrevious()
                    steps += 1
                    continue
                if depth > 0:
                    base_val = _resolve_reg_value(instr.getPrevious(), base_reg, memory, max_back, depth - 1)
                    base_int = base_val.get("value") if base_val else None
                    if base_int is not None:
                        mem_addr = _s64(base_int + offset)
                        loaded = _read_ptr(memory, mem_addr)
                        return {
                            "value": mem_addr,
                            "source": "base+ldr",
                            "instruction": instr.toString(),
                            "mem_addr": mem_addr,
                            "loaded_value": loaded,
                        }
            addr = _first_address_operand(instr)
            if addr is not None:
                loaded = _read_ptr(memory, addr)
                return {
                    "value": addr,
                    "source": "ldr_literal",
                    "instruction": instr.toString(),
                    "mem_addr": addr,
                    "loaded_value": loaded,
                }
        if mnemonic in ("MOV", "MOVZ", "MOVK", "MOVN", "ORR"):
            scalar = _first_scalar_operand(instr)
            if scalar is not None:
                return {"value": _s64(scalar), "source": mnemonic.lower(), "instruction": instr.toString()}
            src_reg = _first_register_operand(instr, 1)
            if src_reg:
                reg_name = src_reg
                instr = instr.getPrevious()
                steps += 1
                continue
        return {"value": None, "source": mnemonic.lower(), "instruction": instr.toString()}
    return {"value": None, "source": "unresolved", "scan_limit": max_back}


def run():
    global _RUN
    if _RUN:
        return
    _RUN = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 2:
            print("usage: kernel_got_load_sweep.py <out_dir> <build_id> [lookback] [all] [refs_only] [target_only=addr1,addr2]")
            return
        out_dir = args[0]
        build_id = args[1]
        lookback = 16
        scan_all = False
        refs_only = False
        target_only = []
        for extra in args[2:]:
            token = str(extra)
            lower = token.lower()
            if lower == "all":
                scan_all = True
                continue
            if lower in ("refs_only", "refs-only", "with_refs_only", "1", "true"):
                refs_only = True
                continue
            if lower.startswith("target_only=") or lower.startswith("target-only="):
                raw = token.split("=", 1)[1]
                for part in raw.split(","):
                    if part.strip():
                        target_only.append(_parse_hex_address(part.strip()))
                continue
            try:
                lookback = int(token)
            except Exception:
                pass

        _ensure(out_dir)
        memory = currentProgram.getMemory()
        listing = currentProgram.getListing()
        func_mgr = currentProgram.getFunctionManager()
        ref_mgr = currentProgram.getReferenceManager()

        blocks = list(memory.getBlocks()) if scan_all else _sandbox_blocks()
        exec_blocks = _exec_blocks(blocks)
        addr_set = _block_set(exec_blocks)
        got_blocks, got_mode = _find_got_blocks(blocks)
        target_only = [t for t in target_only if t is not None]
        target_set = set(target_only)

        hits = []
        counts = {
            "instructions": 0,
            "ref_hits": 0,
            "computed_hits": 0,
            "literal_hits": 0,
            "total_hits": 0,
        }
        instr_iter = listing.getInstructions(addr_set, True)
        while instr_iter.hasNext() and not monitor.isCancelled():
            instr = instr_iter.next()
            if not isinstance(instr, Instruction):
                continue
            counts["instructions"] += 1
            instr_addr = instr.getAddress()
            func = func_mgr.getFunctionContaining(instr_addr)
            block = memory.getBlock(instr_addr)

            # Direct references recorded by Ghidra.
            for ref in ref_mgr.getReferencesFrom(instr_addr):
                to_addr = ref.getToAddress()
                if not to_addr:
                    continue
                got_block = _addr_in_blocks(to_addr.getOffset(), got_blocks)
                if not got_block:
                    continue
                target_addr = _s64(to_addr.getOffset())
                if target_set and target_addr not in target_set:
                    continue
                counts["ref_hits"] += 1
                counts["total_hits"] += 1
                hits.append(
                    {
                        "kind": "ref",
                        "instruction": instr.toString(),
                        "instruction_address": _format_addr(_s64(instr_addr.getOffset())),
                        "function": func.getName() if func else None,
                        "block": block.getName() if block else None,
                        "ref_type": ref.getReferenceType().getName(),
                        "got_address": _format_addr(target_addr),
                        "got_block": got_block.getName(),
                    }
                )

            # Literal address operands (may be redundant with refs but recorded explicitly).
            lit_addr = _first_address_operand(instr)
            if lit_addr is not None:
                got_block = _addr_in_blocks(lit_addr, got_blocks)
                if got_block:
                    if not target_set or lit_addr in target_set:
                        counts["literal_hits"] += 1
                        counts["total_hits"] += 1
                        hits.append(
                            {
                                "kind": "literal",
                                "instruction": instr.toString(),
                                "instruction_address": _format_addr(_s64(instr_addr.getOffset())),
                                "function": func.getName() if func else None,
                                "block": block.getName() if block else None,
                                "got_address": _format_addr(lit_addr),
                                "got_block": got_block.getName(),
                            }
                        )

            if refs_only:
                continue

            if not _is_ldr(instr):
                continue
            base_reg, offset = _parse_mem_operand(instr)
            if not base_reg:
                continue
            resolved = _resolve_reg_value(instr.getPrevious(), base_reg, memory, max_back=lookback, depth=2)
            base_val = resolved.get("value") if resolved else None
            if base_val is None:
                continue
            candidate = _s64(base_val + (offset or 0))
            got_block = _addr_in_blocks(candidate, got_blocks)
            if not got_block:
                continue
            if target_set and candidate not in target_set:
                continue
            counts["computed_hits"] += 1
            counts["total_hits"] += 1
            hits.append(
                {
                    "kind": "computed",
                    "instruction": instr.toString(),
                    "instruction_address": _format_addr(_s64(instr_addr.getOffset())),
                    "function": func.getName() if func else None,
                    "block": block.getName() if block else None,
                    "base_reg": base_reg,
                    "base_value": _format_addr(base_val),
                    "offset": offset,
                    "resolve_source": resolved.get("source"),
                    "resolve_instruction": resolved.get("instruction"),
                    "got_address": _format_addr(candidate),
                    "got_block": got_block.getName(),
                }
            )

        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "lookback": lookback,
            "scan_all_blocks": scan_all,
            "refs_only": refs_only,
            "target_only": [_format_addr(t) for t in target_only],
            "got_block_mode": got_mode,
            "got_blocks": [
                {
                    "name": b.getName(),
                    "start": _format_addr(_s64(b.getStart().getOffset())),
                    "end": _format_addr(_s64(b.getEnd().getOffset())),
                }
                for b in got_blocks
            ],
            "block_filter": [
                {
                    "name": b.getName(),
                    "start": _format_addr(_s64(b.getStart().getOffset())),
                    "end": _format_addr(_s64(b.getEnd().getOffset())),
                    "exec": bool(b.isExecute()),
                }
                for b in exec_blocks
            ],
            "counts": counts,
        }
        with open(os.path.join(out_dir, "got_load_sweep.json"), "w") as f:
            json.dump({"meta": meta, "hits": hits}, f, indent=2, sort_keys=True)
        print("kernel_got_load_sweep: hits %d (refs %d, computed %d, literal %d)" % (counts["total_hits"], counts["ref_hits"], counts["computed_hits"], counts["literal_hits"]))
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
