#@category Sandbox
"""
Summarize one-step provenance for a store instruction.
Args: <out_dir> <build_id> <addr_hex> [max_back]

Outputs: <out_dir>/store_provenance.json

Notes:
- This is a bounded backward scan; it does not attempt full dataflow recovery.
- Disassembly is requested on demand if the listing is sparse.
"""

import json
import os
import traceback

from ghidra.program.model.lang import OperandType, Register

from ghidra_bootstrap import io_utils, scan_utils


_RUN_CALLED = False


def _ensure_out_dir(path):
    return io_utils.ensure_out_dir(path)

def _collect_registers(objs):
    regs = []
    if objs is None:
        return regs
    for obj in objs:
        if isinstance(obj, Register):
            regs.append(obj)
    return regs


def _base_reg_name(reg):
    base = reg.getBaseRegister() if reg and reg.getBaseRegister() is not None else reg
    return base.getName() if base else None


def _memory_operand_index(instr):
    for idx in range(instr.getNumOperands()):
        op_type = instr.getOperandType(idx)
        if op_type & OperandType.ADDRESS:
            return idx
    return None


def _collect_defs(listing, start_addr, target_regs, max_back):
    defs = {}
    cur = listing.getInstructionBefore(start_addr)
    steps = 0
    while cur and steps < max_back and len(defs) < len(target_regs):
        for reg in _collect_registers(cur.getResultObjects()):
            name = _base_reg_name(reg)
            if name in target_regs and name not in defs:
                defs[name] = {
                    "addr": scan_utils.format_address(cur.getAddress().getOffset()),
                    "inst": str(cur),
                }
        cur = listing.getInstructionBefore(cur.getAddress())
        steps += 1
    return defs


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_store_provenance.py <out_dir> <build_id> <addr_hex> [max_back]")
            return
        out_dir = args[0]
        build_id = args[1]
        addr_val = scan_utils.parse_hex(args[2])
        if addr_val is None:
            raise ValueError("Invalid address: %s" % args[2])
        # Keep default scan window small to avoid long backtracking in large functions.
        max_back = int(args[3], 0) if len(args) > 3 else 64

        _ensure_out_dir(out_dir)
        addr_factory = currentProgram.getAddressFactory()
        addr_space = addr_factory.getDefaultAddressSpace()
        addr = addr_space.getAddress(scan_utils.format_address(addr_val))
        listing = currentProgram.getListing()
        instr = listing.getInstructionAt(addr)
        if not instr:
            try:
                # Headless projects may be partially disassembled; request a local decode.
                disassemble(addr)
            except Exception:
                pass
            instr = listing.getInstructionAt(addr)

        if not instr:
            raise ValueError("No instruction at address: %s" % scan_utils.format_address(addr_val))

        mnemonic = instr.getMnemonicString().lower()
        if not (mnemonic.startswith("str") or mnemonic.startswith("stp") or mnemonic.startswith("stur")):
            raise ValueError("Instruction is not a store: %s" % instr)

        mem_idx = _memory_operand_index(instr)
        base_reg_name = None
        if mem_idx is not None:
            mem_regs = _collect_registers(instr.getOpObjects(mem_idx))
            if mem_regs:
                base_reg_name = _base_reg_name(mem_regs[0])

        value_regs = []
        for idx in range(instr.getNumOperands()):
            if idx == mem_idx:
                continue
            for reg in _collect_registers(instr.getOpObjects(idx)):
                name = _base_reg_name(reg)
                if name and name not in value_regs:
                    value_regs.append(name)

        target_regs = list(value_regs)
        if base_reg_name and base_reg_name not in target_regs:
            target_regs.append(base_reg_name)

        defs = _collect_defs(listing, addr, target_regs, max_back)
        defs_list = []
        for name in target_regs:
            if name in defs:
                entry = {"register": name}
                entry.update(defs[name])
                defs_list.append(entry)

        out = {
            "build_id": build_id,
            "address": scan_utils.format_address(addr_val),
            "instruction": str(instr),
            "mnemonic": instr.getMnemonicString(),
            "base_register": base_reg_name,
            "value_registers": value_regs,
            "stack_access": scan_utils.is_stack_access(str(instr)),
            "register_defs": defs_list,
            "unresolved": [r for r in target_regs if r not in defs],
        }
        with open(os.path.join(out_dir, "store_provenance.json"), "w") as f:
            json.dump(out, f, indent=2, sort_keys=True)
        print("kernel_store_provenance: wrote %d defs" % len(defs_list))
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
