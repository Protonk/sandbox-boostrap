#@category Sandbox
"""
Dump a window of instructions around an address.
Args: <out_dir> <build_id> <addr_hex> [before] [after]

Outputs: <out_dir>/addr_window_dump.json
"""

import json
import os
import traceback

from ghidra.program.model.mem import MemoryAccessException

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
            print("usage: kernel_addr_window_dump.py <out_dir> <build_id> <addr_hex> [before] [after]")
            return
        out_dir = args[0]
        build_id = args[1]
        addr_val = _parse_hex_addr(args[2])
        if addr_val is None:
            raise ValueError("Invalid address: %s" % args[2])
        before = _parse_int(args[3], 16) if len(args) > 3 else 16
        after = _parse_int(args[4], 16) if len(args) > 4 else 32

        _ensure_out_dir(out_dir)
        listing = currentProgram.getListing()
        func_mgr = currentProgram.getFunctionManager()
        addr_factory = currentProgram.getAddressFactory()
        addr_space = addr_factory.getDefaultAddressSpace()
        addr = addr_space.getAddress("0x%x" % addr_val)

        inst = listing.getInstructionAt(addr)
        if not inst:
            try:
                disassemble(addr)
            except MemoryAccessException:
                pass
            except Exception:
                pass
            inst = listing.getInstructionAt(addr)

        before_list = []
        cur = inst
        for _ in range(before):
            if cur is None:
                break
            cur = listing.getInstructionBefore(cur.getAddress())
            if cur is None:
                break
            before_list.append(cur)
        before_list.reverse()

        after_list = []
        cur = inst
        if cur is not None:
            after_list.append(cur)
        for _ in range(after):
            if cur is None:
                break
            cur = listing.getInstructionAfter(cur.getAddress())
            if cur is None:
                break
            after_list.append(cur)

        func = func_mgr.getFunctionContaining(addr)
        out = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "address": "0x%x" % addr_val,
            "function": func.getName() if func else None,
            "instructions": [x for x in [_inst_entry(i) for i in (before_list + after_list)] if x],
        }
        with open(os.path.join(out_dir, "addr_window_dump.json"), "w") as f:
            json.dump(out, f, indent=2, sort_keys=True)
        print("kernel_addr_window_dump: wrote %d instructions" % len(out["instructions"]))
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
