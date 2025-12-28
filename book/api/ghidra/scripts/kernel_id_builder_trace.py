#@category Sandbox
"""
Trace list-head and writer candidates for the update_file_by_fileid id builder.
Args: <out_dir> <build_id> <lookup_addr_hex> [list_head_addr_hex] [store_offset_hex]

Outputs: <out_dir>/id_builder_trace.json
"""

import json
import os
import sys
import traceback

from ghidra.program.model.lang import OperandType, Register

try:
    SCRIPT_DIR = os.path.dirname(getSourceFile().getAbsolutePath())
except Exception:
    SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__)) if "__file__" in globals() else os.getcwd()

candidate_paths = [
    os.path.abspath(os.path.join(SCRIPT_DIR, "..")),
    os.path.abspath(os.path.join(os.getcwd(), "book", "api", "ghidra")),
]
for _p in candidate_paths:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from ghidra_lib import scan_utils


_RUN_CALLED = False


def _ensure_out_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


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


def _resolve_adrp_page(instr):
    try:
        repr_text = instr.getDefaultOperandRepresentation(1)
    except Exception:
        repr_text = None
    if not repr_text:
        return None
    try:
        return scan_utils.parse_address(repr_text)
    except Exception:
        return None


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_id_builder_trace.py <out_dir> <build_id> <lookup_addr_hex> [list_head_addr_hex] [store_offset_hex]")
            return
        out_dir = args[0]
        build_id = args[1]
        lookup_addr = scan_utils.parse_address(args[2])
        if lookup_addr is None:
            raise ValueError("Invalid lookup address: %s" % args[2])
        list_head_addr = scan_utils.parse_address(args[3]) if len(args) > 3 else None
        store_offset = int(args[4], 0) if len(args) > 4 else 0xc0
        list_head_offset = 0xfa0

        _ensure_out_dir(out_dir)
        addr_factory = currentProgram.getAddressFactory()
        addr_space = addr_factory.getDefaultAddressSpace()
        listing = currentProgram.getListing()
        func_mgr = currentProgram.getFunctionManager()
        ref_mgr = currentProgram.getReferenceManager()

        lookup = addr_space.getAddress("0x%x" % lookup_addr)
        func = func_mgr.getFunctionContaining(lookup)
        if func is None:
            raise ValueError("No function for lookup addr: 0x%x" % lookup_addr)

        list_head_candidates = []
        for instr in listing.getInstructions(func.getBody(), True):
            inst_text = str(instr)
            if not scan_utils.exact_offset_match(inst_text, list_head_offset):
                continue
            mem_idx = _memory_operand_index(instr)
            if mem_idx is None:
                continue
            mem_regs = _collect_registers(instr.getOpObjects(mem_idx))
            base_name = _base_reg_name(mem_regs[0]) if mem_regs else None
            if not base_name:
                continue
            # walk backward to find matching adrp
            page_addr = None
            prev = listing.getInstructionBefore(instr.getAddress())
            steps = 0
            while prev and steps < 64:
                if prev.getMnemonicString().lower() == "adrp":
                    regs = _collect_registers(prev.getOpObjects(0))
                    reg_name = _base_reg_name(regs[0]) if regs else None
                    if reg_name == base_name:
                        page_addr = _resolve_adrp_page(prev)
                        break
                prev = listing.getInstructionBefore(prev.getAddress())
                steps += 1
            if page_addr is not None:
                list_head = (page_addr + list_head_offset) & ((1 << 64) - 1)
                list_head_candidates.append(
                    {
                        "ldr_addr": "0x%x" % instr.getAddress().getOffset(),
                        "ldr_inst": inst_text,
                        "base_reg": base_name,
                        "adrp_page": scan_utils.format_address(page_addr),
                        "list_head": scan_utils.format_address(list_head),
                    }
                )

        if list_head_addr is not None:
            list_head_candidates.append(
                {
                    "ldr_addr": None,
                    "ldr_inst": None,
                    "base_reg": None,
                    "adrp_page": None,
                    "list_head": scan_utils.format_address(list_head_addr),
                    "source": "arg",
                }
            )

        writer_candidates = []
        for cand in list_head_candidates:
            addr_text = cand.get("list_head")
            if not addr_text:
                continue
            addr_val = scan_utils.parse_address(addr_text)
            if addr_val is None:
                continue
            addr = addr_space.getAddress("0x%x" % addr_val)
            refs = []
            func_entry_map = {}
            for ref in ref_mgr.getReferencesTo(addr):
                from_addr = ref.getFromAddress()
                func_ref = func_mgr.getFunctionContaining(from_addr)
                func_entry = None
                if func_ref:
                    func_entry = "0x%x" % func_ref.getEntryPoint().getOffset()
                    func_entry_map.setdefault(func_ref.getName(), func_entry)
                refs.append(
                    {
                        "from": "0x%x" % from_addr.getOffset(),
                        "function": func_ref.getName() if func_ref else None,
                        "function_entry": func_entry,
                        "type": ref.getReferenceType().getName(),
                        "is_read": ref.getReferenceType().isRead(),
                        "is_write": ref.getReferenceType().isWrite(),
                    }
                )
            refs_by_func = {}
            for ref in refs:
                fn = ref.get("function") or "<no-func>"
                refs_by_func.setdefault(fn, []).append(ref)

            store_hits = []
            for fn in refs_by_func.keys():
                if fn == "<no-func>":
                    continue
                entry_text = func_entry_map.get(fn)
                if not entry_text:
                    continue
                entry_val = scan_utils.parse_address(entry_text)
                if entry_val is None:
                    continue
                entry_addr = addr_space.getAddress("0x%x" % entry_val)
                func_obj = func_mgr.getFunctionAt(entry_addr)
                if func_obj is None:
                    continue
                for instr in listing.getInstructions(func_obj.getBody(), True):
                    inst_text = str(instr)
                    if not scan_utils.exact_offset_match(inst_text, store_offset):
                        continue
                    if scan_utils.is_stack_access(inst_text):
                        continue
                    mnem = instr.getMnemonicString().lower()
                    if not (mnem.startswith("str") or mnem.startswith("stp") or mnem.startswith("stur")):
                        continue
                    store_hits.append(
                        {
                            "function": fn,
                            "addr": "0x%x" % instr.getAddress().getOffset(),
                            "inst": inst_text,
                        }
                    )

            writer_candidates.append(
                {
                    "list_head": scan_utils.format_address(addr_val),
                    "refs": refs,
                    "stores": store_hits,
                }
            )

        out = {
            "build_id": build_id,
            "lookup_addr": scan_utils.format_address(lookup_addr),
            "lookup_function": func.getName() if func else None,
            "list_head_offset": "0x%x" % list_head_offset,
            "store_offset": "0x%x" % store_offset,
            "list_head_candidates": list_head_candidates,
            "writer_candidates": writer_candidates,
        }
        with open(os.path.join(out_dir, "id_builder_trace.json"), "w") as f:
            json.dump(out, f, indent=2, sort_keys=True)
        print("kernel_id_builder_trace: wrote %d candidates" % len(list_head_candidates))
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
