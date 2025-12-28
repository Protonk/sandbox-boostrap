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
    text = token.strip().lower()
    if text.startswith("0x-"):
        text = "-0x" + text[3:]
    val = _parse_int(text)
    if val is None:
        return None
    if val < 0:
        val = (1 << 64) + val
    return val


def _inst_entry(inst):
    if inst is None:
        return None
    return {
        "addr": "0x%x" % inst.getAddress().getOffset(),
        "mnemonic": inst.getMnemonicString(),
        "inst": str(inst),
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
        addr_factory = currentProgram.getAddressFactory()
        addr_space = addr_factory.getDefaultAddressSpace()

        start_addr = addr_val - (before * step)
        end_addr = addr_val + (after * step)
        if start_addr < 0:
            start_addr = 0

        # Ensure disassembly exists across the window.
        cur = start_addr
        while cur <= end_addr and not monitor.isCancelled():
            addr = addr_space.getAddress("0x%x" % cur)
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
            addr = addr_space.getAddress("0x%x" % cur)
            inst = listing.getInstructionAt(addr)
            entry = {"addr": "0x%x" % cur}
            if inst:
                entry.update(_inst_entry(inst))
            entries.append(entry)
            cur += step

        out = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "address": "0x%x" % addr_val,
            "before": before,
            "after": after,
            "step": step,
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
