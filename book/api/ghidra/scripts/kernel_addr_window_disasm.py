#@category Sandbox
"""
Disassemble a fixed-size instruction window around an address and emit a linear dump.
Args: <out_dir> <build_id> <addr_hex> [before] [after] [step]

before/after are instruction counts; step defaults to 4 (AArch64).
Outputs: <out_dir>/addr_window_disasm.json
"""

import json
import os
import traceback

from ghidra.program.model.lang import Register

from ghidra_bootstrap import scan_utils

_RUN_CALLED = False


def _ensure_out_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _parse_int(token, default=None):
    try:
        return int(token, 0)
    except Exception:
        return default


def _parse_hex_addr(token):
    try:
        return scan_utils.parse_hex(token)
    except Exception:
        return None


def _inst_entry(inst):
    if inst is None:
        return None
    return {
        "addr": scan_utils.format_address(inst.getAddress().getOffset()),
        "mnemonic": inst.getMnemonicString(),
        "inst": str(inst),
    }


def _collect_registers(objs):
    regs = []
    if objs is None:
        return regs
    for obj in objs:
        if isinstance(obj, Register):
            regs.append(obj)
    return regs


def _base_reg_name(reg):
    if reg is None:
        return None
    base = reg.getBaseRegister() if reg.getBaseRegister() is not None else reg
    return base.getName()


def _target_context(listing, func_mgr, addr):
    inst = listing.getInstructionAt(addr)
    func = func_mgr.getFunctionContaining(addr)
    block = currentProgram.getMemory().getBlock(addr)
    if not inst:
        return {
            "address": scan_utils.format_address(addr.getOffset()),
            "function": func.getName() if func else None,
            "block": block.getName() if block else None,
            "instruction": None,
            "mnemonic": None,
            "input_registers": [],
            "register_defs": [],
            "stack_access": None,
        }

    try:
        input_objs = inst.getInputObjects()
    except Exception:
        input_objs = []
        for i in range(inst.getNumOperands()):
            input_objs.extend(inst.getOpObjects(i))

    input_regs = []
    for reg in _collect_registers(input_objs):
        name = _base_reg_name(reg)
        if name and name not in input_regs:
            input_regs.append(name)

    defs = {}
    max_back = 64
    cur = listing.getInstructionBefore(addr)
    steps = 0
    while cur and steps < max_back and len(defs) < len(input_regs):
        for reg in _collect_registers(cur.getResultObjects()):
            name = _base_reg_name(reg)
            if name in input_regs and name not in defs:
                defs[name] = {
                    "addr": scan_utils.format_address(cur.getAddress().getOffset()),
                    "inst": str(cur),
                }
        cur = listing.getInstructionBefore(cur.getAddress())
        steps += 1

    register_defs = []
    for name in input_regs:
        if name in defs:
            entry = {"register": name}
            entry.update(defs[name])
            register_defs.append(entry)

    return {
        "address": scan_utils.format_address(addr.getOffset()),
        "function": func.getName() if func else None,
        "block": block.getName() if block else None,
        "instruction": str(inst),
        "mnemonic": inst.getMnemonicString(),
        "input_registers": input_regs,
        "register_defs": register_defs,
        "stack_access": scan_utils.is_stack_access(str(inst)),
    }


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_addr_window_disasm.py <out_dir> <build_id> <addr_hex> [before] [after] [step]")
            return
        out_dir = args[0]
        build_id = args[1]
        addr_val = _parse_hex_addr(args[2])
        if addr_val is None:
            raise ValueError("Invalid address: %s" % args[2])
        before = _parse_int(args[3], 32) if len(args) > 3 else 32
        after = _parse_int(args[4], 32) if len(args) > 4 else 32
        step = _parse_int(args[5], 4) if len(args) > 5 else 4

        _ensure_out_dir(out_dir)
        listing = currentProgram.getListing()
        func_mgr = currentProgram.getFunctionManager()
        addr_factory = currentProgram.getAddressFactory()
        addr_space = addr_factory.getDefaultAddressSpace()

        start_addr = addr_val - (before * step)
        end_addr = addr_val + (after * step)
        if start_addr < 0:
            start_addr = 0

        # Ensure disassembly exists across the window.
        cur = start_addr
        while cur <= end_addr and not monitor.isCancelled():
            addr = addr_space.getAddress(scan_utils.format_address(cur))
            inst = listing.getInstructionAt(addr)
            if not inst:
                try:
                    disassemble(addr)
                except Exception:
                    pass
            cur += step

        entries = []
        cur = start_addr
        while cur <= end_addr and not monitor.isCancelled():
            addr = addr_space.getAddress(scan_utils.format_address(cur))
            inst = listing.getInstructionAt(addr)
            entry = {"addr": scan_utils.format_address(cur)}
            if inst:
                entry.update(_inst_entry(inst))
                entry["stack_access"] = scan_utils.is_stack_access(str(inst))
            entries.append(entry)
            cur += step

        target_addr = addr_space.getAddress(scan_utils.format_address(addr_val))
        out = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "address": scan_utils.format_address(addr_val),
            "before": before,
            "after": after,
            "step": step,
            "target": _target_context(listing, func_mgr, target_addr),
            "instructions": entries,
        }
        with open(os.path.join(out_dir, "addr_window_disasm.json"), "w") as f:
            json.dump(out, f, indent=2, sort_keys=True)
        print("kernel_addr_window_disasm: wrote %d entries" % len(entries))
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
