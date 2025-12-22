#@category Sandbox
"""
Recover mac_policy_register instances from call sites and decode mac_policy_conf fields.

Args:
  <out_dir> <build_id>
  call-sites=<path> fixups=<path> [fileset-index=<path>]
  [mac-policy-register=<addr>] [max-back=<n>]

Outputs: <out_dir>/mac_policy_register_instances.json
"""

import json
import os
import traceback

from ghidra.program.model.address import Address, AddressSet
from ghidra.program.model.lang import Register
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.listing import Instruction
from ghidra.app.plugin.core.analysis import ConstantPropagationContextEvaluator
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.util import SymbolicPropogator

_RUN = False
MASK64 = 0xFFFFFFFFFFFFFFFFL
SIGN_BIT = 0x8000000000000000L
_DECOMP = None
_DECOMP_CACHE = {}
_EXT_OPS = []
for _name in ("SIGNEXT", "INT_SEXT", "INT_ZEXT", "ZEXT"):
    if hasattr(PcodeOp, _name):
        _EXT_OPS.append(getattr(PcodeOp, _name))


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


def _ensure_out_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _load_json(path):
    with open(path, "r") as fh:
        return json.load(fh)


def _load_fixups_map(path):
    fixups = {}
    if not path:
        return fixups
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            vmaddr = rec.get("vmaddr")
            if vmaddr is None:
                continue
            fixups[int(vmaddr)] = rec
    return fixups


def _load_entries(path):
    if not path:
        return []
    data = _load_json(path)
    entries = []
    for entry in data.get("entries", []):
        span = entry.get("vmaddr_span") or {}
        start = span.get("start")
        end = span.get("end")
        if start is None or end is None:
            continue
        entries.append((_s64(long(start)), _s64(long(end)), entry.get("entry_id")))
    return sorted(entries, key=lambda item: item[0])


def _find_entry(entries, vmaddr):
    if vmaddr is None:
        return None
    lo = 0
    hi = len(entries) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        start, end, entry_id = entries[mid]
        if vmaddr < start:
            hi = mid - 1
        elif vmaddr >= end:
            lo = mid + 1
        else:
            return entry_id
    return None


def _read_ptr(memory, addr):
    if addr is None:
        return None
    try:
        return long(memory.getLong(toAddr(_s64(addr))))
    except (MemoryAccessException, Exception):
        return None


def _read_u32(memory, addr):
    if addr is None:
        return None
    try:
        return int(memory.getInt(toAddr(_s64(addr))))
    except (MemoryAccessException, Exception):
        return None


def _read_cstring(memory, addr, max_len=256):
    if addr is None:
        return None
    try:
        a = toAddr(_s64(addr))
    except Exception:
        return None
    out = []
    for _ in range(max_len):
        try:
            b = memory.getByte(a)
        except Exception:
            break
        if b == 0:
            break
        if b < 0:
            b = 256 + b
        if b < 32 or b > 126:
            out.append("?")
        else:
            out.append(chr(b))
        a = a.add(1)
    return "".join(out) if out else None


def _looks_like_string(text):
    if not text:
        return False
    if all(ch == "?" for ch in text):
        return False
    return True


def _resolve_reg_string(start_instr, reg_name, memory, max_back=120):
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
            base = _first_address_or_scalar(instr)
            if base is None:
                instr = instr.getPrevious()
                steps += 1
                continue
            value = _s64(base + pending["delta"]) if pending else _s64(base)
            text = _read_cstring(memory, value)
            if _looks_like_string(text):
                return {"value": value, "string": text, "instruction": instr.toString(), "source": mnemonic.lower()}
        if mnemonic in ("ADD", "SUB"):
            src_reg = _first_register_operand(instr, 1)
            scalar = _first_scalar_operand(instr)
            if scalar is not None and src_reg == reg_name:
                sign = 1 if mnemonic == "ADD" else -1
                pending = {"delta": sign * scalar}
                instr = instr.getPrevious()
                steps += 1
                continue
        if mnemonic.startswith("LDR") or mnemonic.startswith("LDRA") or mnemonic.startswith("LDUR"):
            addr = _first_address_operand(instr)
            if addr is not None:
                loaded = _read_ptr(memory, addr)
                if loaded is not None:
                    text = _read_cstring(memory, loaded)
                    if _looks_like_string(text):
                        return {"value": _s64(loaded), "string": text, "instruction": instr.toString(), "source": "ldr_literal"}
        if mnemonic in ("MOV", "ORR"):
            src_reg = _first_register_operand(instr, 1)
            if src_reg:
                reg_name = src_reg
        instr = instr.getPrevious()
        steps += 1
    return None


def _sp_delta_adjust(instr):
    mnem = instr.getMnemonicString().upper()
    if mnem in ("SUB", "ADD"):
        dst = _first_register_operand(instr, 0)
        src = _first_register_operand(instr, 1)
        scalar = _first_scalar_operand(instr)
        if dst == "sp" and src == "sp" and scalar is not None:
            return scalar if mnem == "SUB" else -scalar
    if (mnem.startswith("STP") or mnem.startswith("LDP")) and "sp" in instr.toString():
        text = instr.toString()
        if "]!" in text:
            base, off = _ldr_base_offset(instr)
            if base == "sp" and off is not None:
                return -off
        if "]," in text:
            scalar = _first_scalar_operand(instr)
            if scalar is not None:
                return -scalar
    return 0


def _looks_like_epilogue_restore(instr, window=6):
    cur = instr
    steps = 0
    while cur and steps < window:
        mnem = cur.getMnemonicString().upper()
        if mnem == "RET":
            return True
        if mnem == "ADD":
            dst = _first_register_operand(cur, 0)
            src = _first_register_operand(cur, 1)
            if dst == "sp" and src == "sp":
                return True
        if mnem.startswith("LDP"):
            text = cur.toString()
            if "x29" in text and "x30" in text and "sp" in text:
                return True
        cur = cur.getNext()
        steps += 1
    return False


def _normalize_reg(name):
    if not name:
        return None
    name = name.lower()
    if name.startswith("w") and name[1:].isdigit():
        return "x" + name[1:]
    return name


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


def _first_scalar_operand(instr):
    from ghidra.program.model.scalar import Scalar

    for i in range(instr.getNumOperands()):
        for obj in instr.getOpObjects(i):
            if isinstance(obj, Scalar):
                try:
                    return obj.getUnsignedValue()
                except Exception:
                    return obj.getValue()
    return None


def _first_address_operand(instr):
    for i in range(instr.getNumOperands()):
        for obj in instr.getOpObjects(i):
            if isinstance(obj, Address):
                return _s64(obj.getOffset())
    return None


def _first_address_or_scalar(instr):
    addr = _first_address_operand(instr)
    if addr is not None:
        return addr
    scalar = _first_scalar_operand(instr)
    if scalar is None:
        return None
    return _s64(scalar)


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


def _ldr_base_offset(instr):
    if instr.getNumOperands() < 2:
        return None, None
    base = None
    offset = 0
    mem_index = instr.getNumOperands() - 1
    for obj in instr.getOpObjects(mem_index):
        if isinstance(obj, Register):
            base = _normalize_reg(obj.getName())
        else:
            try:
                offset = int(obj.getValue())
            except Exception:
                try:
                    offset = int(obj.getUnsignedValue())
                except Exception:
                    pass
    return base, offset


def _resolve_stack_slot(start_instr, base_reg, offset, memory, max_back=60, depth=2):
    instr = start_instr
    steps = 0
    target = offset or 0
    sp_delta = 0
    fp_delta = None
    while instr and steps < max_back and not monitor.isCancelled():
        for store in _store_operands(instr):
            store_base = store.get("base")
            store_off = store.get("offset") or 0
            effective_off = None
            if store_base == base_reg:
                effective_off = store_off + sp_delta
            elif base_reg == "sp" and store_base == "x29":
                if fp_delta is not None:
                    effective_off = store_off + sp_delta + fp_delta
                else:
                    effective_off = store_off + sp_delta
            if effective_off is not None and effective_off == target:
                src_reg = store.get("reg")
                if src_reg:
                    return _resolve_reg_value(instr.getPrevious(), src_reg, memory, max_back=max_back, depth=depth - 1)
        sp_adjust = _sp_delta_adjust(instr)
        if fp_delta is not None:
            fp_delta -= sp_adjust
        sp_delta += sp_adjust
        mnem = instr.getMnemonicString().upper()
        if mnem in ("MOV", "ADD", "SUB"):
            dst = _first_register_operand(instr, 0)
            src = _first_register_operand(instr, 1)
            scalar = _first_scalar_operand(instr)
            if dst == "x29" and src == "sp":
                if mnem == "MOV":
                    fp_delta = 0
                elif mnem == "ADD" and scalar is not None:
                    fp_delta = scalar
                elif mnem == "SUB" and scalar is not None:
                    fp_delta = -scalar
        instr = instr.getPrevious()
        steps += 1
    return {"value": None, "source": "stack_unresolved"}


def _resolve_reg_value(start_instr, reg_name, memory, max_back=40, depth=2, func_body=None):
    instr = start_instr
    steps = 0
    pending = None
    while instr and steps < max_back and not monitor.isCancelled():
        if func_body and not func_body.contains(instr.getAddress()):
            return {"value": None, "source": "func_boundary", "scan_limit": steps}
        if not _writes_reg(instr, reg_name):
            instr = instr.getPrevious()
            steps += 1
            continue
        mnemonic = instr.getMnemonicString().upper()
        if mnemonic in ("ADRP", "ADR"):
            base = _first_address_or_scalar(instr)
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
                        return {
                            "value": value,
                            "source": "%s+%s" % (base_val.get("source"), mnemonic.lower()),
                            "instruction": instr.toString(),
                            "base_reg": src_reg,
                            "delta": sign * scalar,
                            "base_source": base_val.get("source"),
                        }
                    if base_val and base_val.get("value") is None:
                        return {
                            "value": None,
                            "source": "add_symbolic",
                            "instruction": instr.toString(),
                            "base_reg": src_reg,
                            "delta": sign * scalar,
                        }
        if mnemonic.startswith("LDR") or mnemonic.startswith("LDRA") or mnemonic.startswith("LDUR") or mnemonic.startswith("LDP"):
            base_reg, offset = _ldr_base_offset(instr)
            offset = offset or 0
            if mnemonic.startswith("LDP"):
                reg0 = _first_register_operand(instr, 0)
                reg1 = _first_register_operand(instr, 1)
                if reg_name == reg1:
                    offset += _register_size(reg0) or _register_size(reg1) or 8
            if base_reg:
                if base_reg == "sp" and _looks_like_epilogue_restore(instr):
                    instr = instr.getPrevious()
                    steps += 1
                    continue
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
                return {"value": addr, "source": "ldr_literal", "instruction": instr.toString(), "mem_addr": addr, "loaded_value": loaded}
            if base_reg in ("sp", "x29") and depth > 0:
                slot_val = _resolve_stack_slot(instr.getPrevious(), base_reg, offset, memory, max_back=max_back, depth=depth - 1)
                if slot_val.get("value") is not None or slot_val.get("mem_addr") is not None:
                    slot_val["source"] = "stack_" + slot_val.get("source", "slot")
                    return slot_val
            if base_val and base_val.get("value") is None:
                return {
                    "value": None,
                    "source": "mem_base_unresolved",
                    "instruction": instr.toString(),
                    "base_reg": base_reg,
                    "delta": offset,
                }
        if mnemonic in ("MOV", "MOVZ", "MOVK", "MOVN", "ORR"):
            scalar = _first_scalar_operand(instr)
            if scalar is not None:
                return {"value": _s64(scalar), "source": mnemonic.lower(), "instruction": instr.toString()}
            src_reg = _first_register_operand(instr, 1)
            if src_reg:
                prev = instr.getPrevious()
                if src_reg == "x0" and prev:
                    prev_mnem = prev.getMnemonicString().upper()
                    if prev_mnem.startswith("BL"):
                        arg_val = _resolve_reg_value(prev.getPrevious(), "x1", memory, max_back, depth - 1)
                        arg_int = arg_val.get("value") if arg_val else None
                        if arg_int is not None:
                            return {
                                "value": _s64(arg_int),
                                "source": "call_ret_x1",
                                "instruction": instr.toString(),
                                "call_instruction": prev.toString(),
                            }
                reg_name = src_reg
                instr = instr.getPrevious()
                steps += 1
                continue
        return {"value": None, "source": mnemonic.lower(), "instruction": instr.toString()}
    return {"value": None, "source": "unresolved", "scan_limit": max_back}


def _resolve_reg_symbolic(func, addr, reg_name):
    try:
        reg = currentProgram.getRegister(reg_name)
        if reg is None:
            return None
        evaluator = ConstantPropagationContextEvaluator(True)
        prop = SymbolicPropogator(currentProgram)
        prop.flowConstants(func.getEntryPoint(), func.getBody(), evaluator, True, monitor)
        value = prop.getRegisterValue(addr, reg)
        if value is None or not value.hasValue():
            return None
        return value.getValue()
    except Exception:
        return None


def _get_decompiler():
    global _DECOMP
    if _DECOMP is not None:
        return _DECOMP
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    _DECOMP = decomp
    return _DECOMP


def _get_high_function(func):
    key = _s64(func.getEntryPoint().getOffset())
    if key in _DECOMP_CACHE:
        return _DECOMP_CACHE[key]
    decomp = _get_decompiler()
    res = decomp.decompileFunction(func, 30, monitor)
    if res is None or not res.decompileCompleted():
        return None
    high = res.getHighFunction()
    _DECOMP_CACHE[key] = high
    return high


def _resolve_varnode_value(varnode, memory, depth=6):
    if varnode is None:
        return {"value": None, "source": "pcode_none"}
    if depth <= 0:
        return {"value": None, "source": "pcode_depth"}
    try:
        if varnode.isConstant():
            return {"value": _s64(varnode.getOffset()), "source": "pcode_const"}
        if varnode.isAddress():
            return {"value": _s64(varnode.getAddress().getOffset()), "source": "pcode_addr"}
    except Exception:
        pass
    def_op = varnode.getDef()
    if def_op is None:
        return {"value": None, "source": "pcode_nodef"}
    opcode = def_op.getOpcode()
    if opcode in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.SUBPIECE) or opcode in _EXT_OPS:
        return _resolve_varnode_value(def_op.getInput(0), memory, depth - 1)
    if opcode in (PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.PTRSUB):
        left = _resolve_varnode_value(def_op.getInput(0), memory, depth - 1)
        right = _resolve_varnode_value(def_op.getInput(1), memory, depth - 1)
        left_val = left.get("value")
        right_val = right.get("value")
        if left_val is not None and right_val is not None:
            if opcode == PcodeOp.INT_SUB:
                return {"value": _s64(left_val - right_val), "source": "pcode_sub"}
            return {"value": _s64(left_val + right_val), "source": "pcode_add"}
    if opcode == PcodeOp.PTRADD:
        base = _resolve_varnode_value(def_op.getInput(0), memory, depth - 1)
        index = _resolve_varnode_value(def_op.getInput(1), memory, depth - 1)
        scale = _resolve_varnode_value(def_op.getInput(2), memory, depth - 1)
        base_val = base.get("value")
        index_val = index.get("value")
        scale_val = scale.get("value")
        if base_val is not None and index_val is not None and scale_val is not None:
            return {"value": _s64(base_val + (index_val * scale_val)), "source": "pcode_ptradd"}
    if opcode == PcodeOp.LOAD:
        addr_info = _resolve_varnode_value(def_op.getInput(1), memory, depth - 1)
        addr_val = addr_info.get("value")
        if addr_val is not None:
            raw = _read_ptr(memory, addr_val)
            return {"value": None, "mem_addr": addr_val, "loaded_value": raw, "source": "pcode_load", "addr_source": addr_info.get("source")}
    return {"value": None, "source": "pcode_unresolved"}


def _canonicalize_pointer(raw, memory):
    if raw is None:
        return None
    raw_val = _s64(raw)
    candidates = [raw_val]
    for bits in (56, 52, 48):
        mask = (1 << bits) - 1
        cand = raw_val & mask
        if cand & (1 << (bits - 1)):
            cand -= 1 << bits
        candidates.append(cand)
    for cand in candidates:
        try:
            if memory.contains(toAddr(_s64(cand))):
                return _s64(cand)
        except Exception:
            continue
    return None


def _resolve_call_arg_decomp(func, call_addr, arg_index, memory):
    high = _get_high_function(func)
    if high is None:
        return None
    try:
        ops = high.getPcodeOps(call_addr)
    except Exception:
        ops = None
    if ops is None:
        return None
    while ops.hasNext():
        op = ops.next()
        opcode = op.getOpcode()
        if opcode not in (PcodeOp.CALL, PcodeOp.CALLIND):
            continue
        if op.getNumInputs() <= arg_index:
            continue
        arg = op.getInput(arg_index)
        return _resolve_varnode_value(arg, memory)
    return None


def _resolve_callsite_argument(caller_func, call_addr, arg_index, listing, memory, max_back=60):
    resolved = None
    if caller_func:
        resolved = _resolve_call_arg_decomp(caller_func, call_addr, arg_index, memory)
        if resolved and resolved.get("value") is None and resolved.get("mem_addr") is None:
            resolved = None
    if resolved is None:
        instr = listing.getInstructionAt(call_addr)
        if instr:
            reg_name = "x%d" % (arg_index - 1)
            resolved = _resolve_reg_value(
                instr.getPrevious(),
                reg_name,
                memory,
                max_back=max_back,
                depth=2,
                func_body=caller_func.getBody() if caller_func else None,
            )
    return resolved


def _resolve_callers_arg(target_func, arg_index, listing, memory, fixups_map, max_back=60):
    if target_func is None:
        return []
    ref_mgr = currentProgram.getReferenceManager()
    func_mgr = currentProgram.getFunctionManager()
    candidates = []
    for ref in ref_mgr.getReferencesTo(target_func.getEntryPoint()):
        try:
            if not ref.getReferenceType().isCall():
                continue
        except Exception:
            continue
        call_addr = ref.getFromAddress()
        caller_func = func_mgr.getFunctionContaining(call_addr)
        res = _resolve_callsite_argument(caller_func, call_addr, arg_index, listing, memory, max_back=max_back)
        candidate = {
            "call_site": _format_addr(_s64(call_addr.getOffset())),
            "caller_function": {
                "name": caller_func.getName() if caller_func else None,
                "entry": _format_addr(_s64(caller_func.getEntryPoint().getOffset())) if caller_func else None,
            },
            "resolution": res,
        }
        if res:
            if res.get("mem_addr") is not None:
                ptr_info = _resolve_pointer_at(res.get("mem_addr"), res.get("loaded_value"), fixups_map, memory)
                candidate["pointer"] = ptr_info
                candidate["resolved"] = ptr_info.get("resolved")
            elif res.get("value") is not None:
                ptr_info = _resolve_pointer_at(None, res.get("value"), fixups_map, memory)
                candidate["pointer"] = ptr_info
                candidate["resolved"] = ptr_info.get("resolved")
        candidates.append(candidate)
    return candidates


def _select_unique_resolved(candidates):
    values = []
    for candidate in candidates or []:
        if candidate.get("resolved") is not None:
            values.append(candidate.get("resolved"))
    if not values:
        return None
    unique = set(values)
    if len(unique) == 1:
        return values[0]
    return None


def _resolve_base_from_data_refs(target_func, delta, memory, fixups_map, window=0x40):
    if target_func is None or delta is None:
        return {"candidates": [], "chosen": None}
    ref_mgr = currentProgram.getReferenceManager()
    candidates = []
    for ref in ref_mgr.getReferencesTo(target_func.getEntryPoint()):
        try:
            if not ref.getReferenceType().isData():
                continue
        except Exception:
            continue
        ref_addr = ref.getFromAddress()
        ref_off = _s64(ref_addr.getOffset())
        for off in range(-window, window + 1, 8):
            slot_addr = _s64(ref_off + off)
            raw = _read_ptr(memory, slot_addr)
            ptr_info = _resolve_pointer_at(slot_addr, raw, fixups_map, memory)
            base = ptr_info.get("resolved")
            if base is None:
                continue
            ops_addr = _s64(base + delta)
            block = None
            ops_block = None
            try:
                block = memory.getBlock(toAddr(_s64(base)))
                ops_block = memory.getBlock(toAddr(_s64(ops_addr)))
            except Exception:
                block = None
                ops_block = None
            candidates.append(
                {
                    "ref_addr": _format_addr(ref_off),
                    "slot_addr": _format_addr(slot_addr),
                    "pointer": ptr_info,
                    "base_block": block.getName() if block else None,
                    "ops_addr": _format_addr(ops_addr),
                    "ops_block": ops_block.getName() if ops_block else None,
                    "ops_block_write": ops_block.isWrite() if ops_block else None,
                }
            )
    write_bases = []
    for cand in candidates:
        ptr = cand.get("pointer") or {}
        base = ptr.get("resolved")
        if base is None:
            continue
        if cand.get("ops_block_write"):
            write_bases.append(base)
    if write_bases:
        unique = set(write_bases)
        if len(unique) == 1:
            return {"candidates": candidates, "chosen": write_bases[0]}
    return {"candidates": candidates, "chosen": None}


def _resolve_pointer_at(addr, raw, fixups_map, memory):
    addr_key = _u64(addr)
    entry = fixups_map.get(int(addr_key)) if addr_key is not None else None
    if entry:
        resolved = entry.get("resolved_unsigned")
        if resolved is None:
            resolved = entry.get("resolved_guess")
        if resolved is None:
            resolved = entry.get("resolved")
        resolved_signed = _s64(resolved) if resolved is not None else None
        return {
            "raw": raw,
            "resolved": resolved_signed,
            "fixup": {
                "decoded": entry.get("decoded"),
                "resolved_guess": resolved,
                "resolved_signed": resolved_signed,
                "is_auth": entry.get("decoded", {}).get("is_auth") if entry.get("decoded") else None,
                "cache_level": entry.get("decoded", {}).get("cache_level") if entry.get("decoded") else None,
            },
            "status": "fixup_resolved" if resolved is not None else "fixup_unresolved",
        }
    # fallback: raw pointer if it looks like it lives in memory
    resolved = None
    status = "raw_unresolved"
    if raw is not None:
        try:
            addr_obj = toAddr(_s64(raw))
            if memory.contains(addr_obj):
                resolved = _s64(raw)
                status = "raw_in_range"
        except Exception:
            resolved = None
    if resolved is None and raw is not None:
        canonical = _canonicalize_pointer(raw, memory)
        if canonical is not None:
            resolved = canonical
            status = "raw_canonicalized"
    return {"raw": raw, "resolved": resolved, "fixup": None, "status": status}


def _register_size(reg_name):
    if not reg_name:
        return 0
    return 8 if reg_name.startswith("x") else 4


def _arg_index_from_reg(reg_name):
    if not reg_name:
        return None
    name = _normalize_reg(reg_name)
    if not name or not name.startswith("x"):
        return None
    try:
        idx = int(name[1:])
    except Exception:
        return None
    if idx < 0 or idx > 7:
        return None
    return idx + 1


def _store_operands(instr):
    mnem = instr.getMnemonicString().upper()
    if not (mnem.startswith("STR") or mnem.startswith("STUR") or mnem.startswith("STP")):
        return []
    base_reg, offset = _ldr_base_offset(instr)
    offset = offset or 0
    regs = []
    for obj in instr.getOpObjects(0):
        if isinstance(obj, Register):
            regs.append(_normalize_reg(obj.getName()))
    if mnem.startswith("STP"):
        for obj in instr.getOpObjects(1):
            if isinstance(obj, Register):
                regs.append(_normalize_reg(obj.getName()))
        if len(regs) >= 2:
            size = _register_size(regs[0]) or 8
            return [
                {"reg": regs[0], "base": base_reg, "offset": offset},
                {"reg": regs[1], "base": base_reg, "offset": offset + size},
            ]
    if regs:
        return [{"reg": regs[0], "base": base_reg, "offset": offset}]
    return []


def _resolve_store_value(instr, src_reg, memory, fixups_map, max_back=40):
    res = _resolve_reg_value(instr.getPrevious(), src_reg, memory, max_back=max_back, depth=2)
    base_info = None
    if res.get("base_reg") and res.get("delta") is not None:
        base_reg = res.get("base_reg")
        base_res = _resolve_reg_value(instr.getPrevious(), base_reg, memory, max_back=max_back, depth=2)
        base_val = base_res.get("value") if base_res else None
        if base_val is None and base_res and base_res.get("mem_addr") is not None:
            base_ptr = _resolve_pointer_at(base_res.get("mem_addr"), base_res.get("loaded_value"), fixups_map, memory)
            base_val = base_ptr.get("resolved")
        if base_val is not None:
            candidate = _s64(base_val + res.get("delta"))
            try:
                if memory.contains(toAddr(_s64(candidate))):
                    res = dict(res)
                    res["value"] = candidate
                    res["source"] = res.get("source", "expr") + "+base"
                    res["expr_base_value"] = _format_addr(base_val)
                    base_info = base_res
            except Exception:
                pass
    info = {"reg": src_reg, "resolution": res}
    if base_info:
        info["expr_base_resolution"] = base_info
    if res.get("mem_addr") is not None:
        ptr = _resolve_pointer_at(res.get("mem_addr"), res.get("loaded_value"), fixups_map, memory)
        info["pointer"] = ptr
        info["resolved"] = ptr.get("resolved")
    elif res.get("value") is not None:
        ptr = _resolve_pointer_at(None, res.get("value"), fixups_map, memory)
        info["pointer"] = ptr
        info["resolved"] = ptr.get("resolved")
    return info


def _recover_fields_from_stores(call_instr, base_addr, base_reg, base_offset, memory, fixups_map, caller_func=None, listing=None, max_back=200):
    fields = {}
    field_offsets = {0x0: "mpc_name", 0x8: "mpc_fullname", 0x20: "mpc_ops"}
    instr = call_instr.getPrevious()
    steps = 0
    while instr and steps < max_back and not monitor.isCancelled():
        for store in _store_operands(instr):
            src_reg = store.get("reg")
            store_base = store.get("base")
            store_off = store.get("offset") or 0
            if not store_base or not src_reg:
                continue
            field_off = None
            if base_reg and store_base == base_reg:
                field_off = _s64(store_off - (base_offset or 0))
            elif base_addr is not None:
                base_res = _resolve_reg_value(instr.getPrevious(), store_base, memory, max_back=40, depth=2)
                base_val = base_res.get("value") if base_res else None
                if base_val is not None:
                    store_addr = _s64(base_val + store_off)
                    field_off = _s64(store_addr - base_addr)
            if field_off in field_offsets and field_offsets[field_off] not in fields:
                value_info = _resolve_store_value(instr, src_reg, memory, fixups_map, max_back=max_back)
                resolved = value_info.get("resolved")
                field_name = field_offsets[field_off]
                if field_name == "mpc_ops" and resolved is None:
                    res = value_info.get("resolution", {})
                    base_reg_hint = res.get("base_reg")
                    delta = res.get("delta")
                    if base_reg_hint and delta is not None:
                        value_info["symbolic_expr"] = {"base_reg": base_reg_hint, "delta": delta}
                        if base_reg and base_offset is not None:
                            value_info["relative_to_mpc_base"] = {
                                "base_reg": base_reg,
                                "base_reg_hint": base_reg_hint,
                                "delta": _s64(delta - (base_offset or 0)),
                            }
                    arg_index = _arg_index_from_reg(base_reg_hint)
                    if arg_index and caller_func and listing:
                        candidates = _resolve_callers_arg(caller_func, arg_index, listing, memory, fixups_map, max_back=max_back)
                        value_info["caller_base_candidates"] = candidates
                        chosen = _select_unique_resolved(candidates)
                        if chosen is not None and delta is not None:
                            resolved = _s64(chosen + delta)
                            value_info["caller_base_resolved"] = _format_addr(chosen)
                            value_info["resolved"] = resolved
                            value_info["pointer"] = _resolve_pointer_at(None, resolved, fixups_map, memory)
                        elif delta is not None and caller_func:
                            data_ref = _resolve_base_from_data_refs(caller_func, delta, memory, fixups_map, window=0x80)
                            value_info["data_ref_candidates"] = data_ref.get("candidates")
                            chosen = data_ref.get("chosen")
                            if chosen is None:
                                func_mgr = currentProgram.getFunctionManager()
                                passthrough = []
                                for cand in candidates:
                                    res = (cand.get("resolution") or {})
                                    if res.get("source") not in ("func_boundary", "unresolved"):
                                        continue
                                    entry_text = (cand.get("caller_function") or {}).get("entry")
                                    entry_val = _parse_hex(entry_text) if entry_text else None
                                    if entry_val is None:
                                        continue
                                    caller_obj = func_mgr.getFunctionAt(toAddr(_s64(entry_val)))
                                    data_ref = _resolve_base_from_data_refs(caller_obj, delta, memory, fixups_map, window=0x200)
                                    passthrough.extend(data_ref.get("candidates") or [])
                                    if data_ref.get("chosen") is not None:
                                        chosen = data_ref.get("chosen")
                                        value_info["data_ref_base_from"] = entry_text
                                        break
                                if passthrough:
                                    value_info["data_ref_passthrough_candidates"] = passthrough
                            if chosen is not None:
                                resolved = _s64(chosen + delta)
                                value_info["data_ref_base_resolved"] = _format_addr(chosen)
                                value_info["resolved"] = resolved
                                value_info["pointer"] = _resolve_pointer_at(None, resolved, fixups_map, memory)
                string_val = _read_cstring(memory, resolved)
                if field_name in ("mpc_name", "mpc_fullname") and not _looks_like_string(string_val):
                    scan_limit = max_back * 3 if max_back else 300
                    if scan_limit > 800:
                        scan_limit = 800
                    alt = _resolve_reg_string(instr.getPrevious(), src_reg, memory, max_back=scan_limit)
                    if alt and _looks_like_string(alt.get("string")):
                        resolved = alt.get("value")
                        string_val = alt.get("string")
                        value_info["string_fallback"] = alt
                fields[field_name] = {
                    "field_offset": field_off,
                    "store_instruction": instr.toString(),
                    "store_base": store_base,
                    "store_offset": store_off,
                    "store_value": value_info,
                    "value": _format_addr(resolved),
                    "string": string_val,
                }
        if len(fields) >= 3:
            break
        instr = instr.getPrevious()
        steps += 1
    return fields


def _recover_ops_from_stores(call_instr, ops_base_reg, ops_base_offset, memory, fixups_map, entries, max_back=800, scan_bytes=0x800):
    if not ops_base_reg or ops_base_offset is None:
        return None
    ops_entries = {}
    instr = call_instr.getPrevious()
    steps = 0
    max_off = (ops_base_offset or 0) + scan_bytes
    while instr and steps < max_back and not monitor.isCancelled():
        for store in _store_operands(instr):
            store_base = store.get("base")
            store_off = store.get("offset") or 0
            src_reg = store.get("reg")
            if store_base != ops_base_reg or not src_reg:
                continue
            if store_off < ops_base_offset or store_off >= max_off:
                continue
            rel_off = _s64(store_off - ops_base_offset)
            if rel_off in ops_entries:
                continue
            value_info = _resolve_store_value(instr, src_reg, memory, fixups_map, max_back=120)
            resolved = value_info.get("resolved")
            ops_entries[rel_off] = {
                "offset": rel_off,
                "store_instruction": instr.toString(),
                "store_base": store_base,
                "store_offset": store_off,
                "store_value": value_info,
                "resolved": _format_addr(resolved),
                "resolved_value": resolved,
                "owner_entry": _find_entry(entries, resolved) if resolved is not None else None,
            }
        instr = instr.getPrevious()
        steps += 1
    if not ops_entries:
        return None
    return [ops_entries[key] for key in sorted(ops_entries.keys())]


def _address_from_varnode(varnode):
    if varnode is None:
        return None
    try:
        if varnode.isConstant():
            return {"base": None, "offset": 0, "absolute": _s64(varnode.getOffset())}
    except Exception:
        pass
    def_op = varnode.getDef()
    if def_op is None:
        return None
    opcode = def_op.getOpcode()
    if opcode in (PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.PTRSUB):
        left = def_op.getInput(0)
        right = def_op.getInput(1)
        if right and right.isConstant():
            off = _s64(right.getOffset())
            if opcode in (PcodeOp.INT_SUB, PcodeOp.PTRSUB):
                off = _s64(-off)
            return {"base": left, "offset": off, "absolute": None}
        if left and left.isConstant():
            off = _s64(left.getOffset())
            return {"base": right, "offset": off, "absolute": None}
    if opcode == PcodeOp.PTRADD:
        base = def_op.getInput(0)
        index = def_op.getInput(1)
        scale = def_op.getInput(2)
        if index and index.isConstant() and scale and scale.isConstant():
            off = _s64(index.getOffset() * scale.getOffset())
            return {"base": base, "offset": off, "absolute": None}
    return None


def _trace_load_offset(varnode, depth=6):
    if varnode is None or depth <= 0:
        return None
    def_op = varnode.getDef()
    if def_op is None:
        return None
    opcode = def_op.getOpcode()
    if opcode in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.MULTIEQUAL, PcodeOp.SUBPIECE) or opcode in _EXT_OPS:
        return _trace_load_offset(def_op.getInput(0), depth - 1)
    if opcode == PcodeOp.LOAD:
        addr = _address_from_varnode(def_op.getInput(1))
        if addr and addr.get("offset") is not None:
            return {"offset": addr.get("offset"), "base": addr.get("base")}
    return None


def _find_ops_init_offsets(func):
    offsets = set()
    high = _get_high_function(func)
    if high is not None:
        ops_iter = high.getPcodeOps()
        while ops_iter.hasNext():
            op = ops_iter.next()
            if op.getOpcode() != PcodeOp.CALLIND:
                continue
            target = op.getInput(0)
            if target is None:
                continue
            target_load = _trace_load_offset(target, depth=6)
            if not target_load:
                continue
            offset = target_load.get("offset")
            base_var = target_load.get("base")
            if offset is None or base_var is None:
                continue
            base_load = _trace_load_offset(base_var, depth=6)
            if base_load and base_load.get("offset") == 0x20:
                offsets.add(offset)
    if offsets:
        return sorted(list(offsets))

    # Fallback: instruction-level tracking inside mac_policy_register.
    listing = currentProgram.getListing()
    instr_iter = listing.getInstructions(func.getBody(), True)
    mpc_regs = set(["x0"])
    ops_regs = set()
    reg_to_offset = {}
    while instr_iter.hasNext() and not monitor.isCancelled():
        instr = instr_iter.next()
        mnem = instr.getMnemonicString().upper()
        if mnem in ("MOV", "ORR"):
            dst = _first_register_operand(instr, 0)
            src = _first_register_operand(instr, 1)
            if dst and src:
                if src in mpc_regs:
                    mpc_regs.add(dst)
                if src in ops_regs:
                    ops_regs.add(dst)
        if mnem.startswith("LDR") or mnem.startswith("LDUR"):
            dst = _first_register_operand(instr, 0)
            base, off = _ldr_base_offset(instr)
            off = off or 0
            if base in mpc_regs and off == 0x20 and dst:
                ops_regs.add(dst)
            if base in ops_regs and dst:
                reg_to_offset[dst] = off
        if mnem.startswith("BLR"):
            target = _first_register_operand(instr, 0)
            if target in reg_to_offset:
                offsets.add(reg_to_offset[target])
    return sorted(list(offsets))


def _is_exec_addr(memory, addr):
    if addr is None:
        return False
    try:
        blk = memory.getBlock(toAddr(_s64(addr)))
    except Exception:
        return False
    return bool(blk and blk.isExecute())


def _ops_owner_histogram(ops_addr, memory, entries, fixups_map, scan_bytes=0x800):
    if ops_addr is None:
        return None
    slots = int(scan_bytes // 8)
    hist = {}
    resolved_ptrs = 0
    exec_ptrs = 0
    for idx in range(slots):
        slot_addr = _s64(ops_addr + (idx * 8))
        raw = _read_ptr(memory, slot_addr)
        ptr_info = _resolve_pointer_at(slot_addr, raw, fixups_map, memory)
        resolved = ptr_info.get("resolved")
        if resolved is None:
            continue
        resolved_ptrs += 1
        if not _is_exec_addr(memory, resolved):
            continue
        exec_ptrs += 1
        owner = _find_entry(entries, resolved)
        if owner:
            hist[owner] = hist.get(owner, 0) + 1
    top = None
    if hist:
        top = max(hist.items(), key=lambda item: item[1])[0]
    return {
        "scan_bytes": scan_bytes,
        "slots": slots,
        "resolved_ptrs": resolved_ptrs,
        "exec_ptrs": exec_ptrs,
        "owner_histogram": hist,
        "owner_top": top,
    }


def run():
    global _RUN
    if _RUN:
        return
    _RUN = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 4:
            print("usage: kernel_mac_policy_register_instances.py <out_dir> <build_id> call-sites=<path> fixups=<path> [fileset-index=<path>] [mac-policy-register=<addr>] [max-back=<n>]")
            return
        out_dir = args[0]
        build_id = args[1]
        call_sites_path = None
        fixups_path = None
        fileset_index_path = None
        mac_policy_register_addr = None
        max_back = 40
        for arg in args[2:]:
            val = str(arg)
            low = val.lower()
            if low.startswith("call-sites=") or low.startswith("call_sites="):
                call_sites_path = val.split("=", 1)[1]
                continue
            if low.startswith("fixups="):
                fixups_path = val.split("=", 1)[1]
                continue
            if low.startswith("fileset-index=") or low.startswith("fileset_index="):
                fileset_index_path = val.split("=", 1)[1]
                continue
            if low.startswith("mac-policy-register=") or low.startswith("mac_policy_register="):
                mac_policy_register_addr = val.split("=", 1)[1]
                continue
            if low.startswith("max-back="):
                try:
                    max_back = int(val.split("=", 1)[1])
                except Exception:
                    pass

        if not call_sites_path or not fixups_path:
            print("Missing call-sites or fixups path.")
            return

        _ensure_out_dir(out_dir)
        call_sites = _load_json(call_sites_path)
        fixups_map = _load_fixups_map(fixups_path)
        entries = _load_entries(fileset_index_path)

        memory = currentProgram.getMemory()
        listing = currentProgram.getListing()
        func_mgr = currentProgram.getFunctionManager()

        mac_policy_func = None
        if mac_policy_register_addr:
            addr_val = _parse_hex(mac_policy_register_addr)
            if addr_val is not None:
                addr = toAddr(_s64(addr_val))
                mac_policy_func = getFunctionAt(addr)
        if not mac_policy_func:
            mac_policy_func = getGlobalFunctions("mac_policy_register")
            if mac_policy_func:
                mac_policy_func = mac_policy_func[0]

        mpo_policy_init_offsets = []
        if mac_policy_func:
            mpo_policy_init_offsets = _find_ops_init_offsets(mac_policy_func)

        results = []
        for call in call_sites.get("call_sites", []):
            call_addr_text = call.get("call_address")
            call_addr_val = _parse_hex(call_addr_text)
            if call_addr_val is None:
                continue
            call_addr = toAddr(_s64(call_addr_val))
            instr = listing.getInstructionAt(call_addr)
            if not instr:
                continue
            caller_func = func_mgr.getFunctionContaining(call_addr)
            attempts = {}
            resolved = None
            if caller_func:
                decomp = _resolve_call_arg_decomp(caller_func, call_addr, 1, memory)
                attempts["decompiler"] = decomp
                if decomp and (decomp.get("value") is not None or decomp.get("mem_addr") is not None):
                    resolved = decomp
            if resolved is None:
                backtrack = _resolve_reg_value(instr.getPrevious(), "x0", memory, max_back=max_back, depth=2)
                attempts["backtrack"] = backtrack
                if backtrack.get("value") is not None or backtrack.get("mem_addr") is not None:
                    resolved = backtrack
            if resolved is None and caller_func:
                sym_val = _resolve_reg_symbolic(caller_func, call_addr, "x0")
                if sym_val is not None:
                    resolved = {
                        "value": _s64(sym_val),
                        "source": "symbolic",
                        "instruction": None,
                    }
                    attempts["symbolic"] = resolved
            if resolved is None:
                resolved = {"value": None, "source": "unresolved"}
                attempts.setdefault("symbolic", {"value": None, "source": "unresolved"})
            mem_addr = resolved.get("mem_addr")
            loaded_value = resolved.get("loaded_value")
            base_reg = resolved.get("base_reg")
            base_offset = resolved.get("delta") or 0

            mpc_addr = None
            mpc_resolution = {}
            if mem_addr is not None:
                ptr_info = _resolve_pointer_at(mem_addr, loaded_value, fixups_map, memory)
                mpc_addr = ptr_info.get("resolved")
                mpc_resolution = {
                    "mem_addr": _format_addr(mem_addr),
                    "raw": _format_addr(loaded_value),
                    "resolution": ptr_info,
                }
            else:
                mpc_addr = resolved.get("value")
                mpc_resolution = {"mem_addr": None, "raw": _format_addr(mpc_addr), "resolution": {"status": "value"}}

            mpc_fields = {}
            if mpc_addr is not None:
                mpc_block = None
                try:
                    mpc_block = memory.getBlock(toAddr(_s64(mpc_addr)))
                except Exception:
                    mpc_block = None
                name_addr = _s64(_read_ptr(memory, mpc_addr + 0x0))
                fullname_addr = _s64(_read_ptr(memory, mpc_addr + 0x8))
                labelnames_addr = _s64(_read_ptr(memory, mpc_addr + 0x10))
                labelcount = _read_u32(memory, mpc_addr + 0x18)
                ops_addr = _s64(_read_ptr(memory, mpc_addr + 0x20))
                loadtime_flags = _read_u32(memory, mpc_addr + 0x28)
                runtime_flags = _read_u32(memory, mpc_addr + 0x2C)

                name_info = _resolve_pointer_at(mpc_addr + 0x0, name_addr, fixups_map, memory)
                fullname_info = _resolve_pointer_at(mpc_addr + 0x8, fullname_addr, fixups_map, memory)
                labelnames_info = _resolve_pointer_at(mpc_addr + 0x10, labelnames_addr, fixups_map, memory)
                ops_info = _resolve_pointer_at(mpc_addr + 0x20, ops_addr, fixups_map, memory)

                mpc_fields = {
                    "mpc_addr": _format_addr(mpc_addr),
                    "mpc_block": mpc_block.getName() if mpc_block else None,
                    "mpc_fileset_entry": _find_entry(entries, _s64(mpc_addr)),
                    "mpc_name_ptr": name_info,
                    "mpc_fullname_ptr": fullname_info,
                    "mpc_labelnames_ptr": labelnames_info,
                    "mpc_labelname_count": labelcount,
                    "mpc_ops_ptr": ops_info,
                    "mpc_ops_fileset_entry": _find_entry(entries, ops_info.get("resolved")),
                    "mpc_loadtime_flags": loadtime_flags,
                    "mpc_runtime_flags": runtime_flags,
                    "mpc_name": _read_cstring(memory, name_info.get("resolved")),
                    "mpc_fullname": _read_cstring(memory, fullname_info.get("resolved")),
                }

                if labelcount is not None and labelcount > 0 and labelcount < 64:
                    labelnames = []
                    base = labelnames_info.get("resolved")
                    if base is not None:
                        for idx in range(labelcount):
                            raw_ptr = _s64(_read_ptr(memory, base + (idx * 8)))
                            label_ptr_info = _resolve_pointer_at(base + (idx * 8), raw_ptr, fixups_map, memory)
                            labelnames.append(
                                {
                                    "index": idx,
                                    "ptr": label_ptr_info,
                                    "value": _read_cstring(memory, label_ptr_info.get("resolved")),
                                }
                            )
                    mpc_fields["mpc_labelnames"] = labelnames

                if ops_info.get("resolved") is not None and mpo_policy_init_offsets:
                    init_entries = []
                    for offset in mpo_policy_init_offsets:
                        raw_ptr = _s64(_read_ptr(memory, ops_info.get("resolved") + offset))
                        init_ptr_info = _resolve_pointer_at(ops_info.get("resolved") + offset, raw_ptr, fixups_map, memory)
                        init_entries.append(
                            {
                                "offset": offset,
                                "ptr": init_ptr_info,
                                "owner_entry": _find_entry(entries, init_ptr_info.get("resolved")),
                            }
                        )
                    mpc_fields["mpo_policy_init"] = init_entries

            reconstructed = None
            needs_reconstruct = False
            if not mpc_fields:
                needs_reconstruct = True
            else:
                if not mpc_fields.get("mpc_name") and not mpc_fields.get("mpc_fullname"):
                    if not (mpc_fields.get("mpc_ops_ptr") or {}).get("resolved"):
                        needs_reconstruct = True
            if needs_reconstruct:
                rec_fields = _recover_fields_from_stores(
                    instr,
                    mpc_addr,
                    base_reg,
                    base_offset,
                    memory,
                    fixups_map,
                    caller_func=caller_func,
                    listing=listing,
                    max_back=max_back,
                )
                if rec_fields:
                    reconstructed = {
                        "base": {
                            "addr": _format_addr(mpc_addr),
                            "reg": base_reg,
                            "offset": base_offset,
                        },
                        "fields": rec_fields,
                    }
                    if not mpc_fields:
                        mpc_fields = {"mpc_addr": _format_addr(mpc_addr)}
                    if not mpc_fields.get("mpc_name"):
                        mpc_fields["mpc_name"] = rec_fields.get("mpc_name", {}).get("string")
                    if not mpc_fields.get("mpc_fullname"):
                        mpc_fields["mpc_fullname"] = rec_fields.get("mpc_fullname", {}).get("string")
                    if not (mpc_fields.get("mpc_ops_ptr") or {}).get("resolved"):
                        resolved_ops = rec_fields.get("mpc_ops", {}).get("value")
                        if resolved_ops:
                            mpc_fields["mpc_ops_ptr"] = {
                                "raw": resolved_ops,
                                "resolved": _parse_hex(resolved_ops),
                                "fixup": None,
                                "status": "reconstructed",
                            }
                            mpc_fields["mpc_ops_fileset_entry"] = _find_entry(
                                entries, _parse_hex(resolved_ops)
                            )
                    if mpo_policy_init_offsets and mpc_fields.get("mpc_ops_ptr"):
                        ops_resolved = mpc_fields.get("mpc_ops_ptr", {}).get("resolved")
                        if ops_resolved is not None and "mpo_policy_init" not in mpc_fields:
                            init_entries = []
                            for offset in mpo_policy_init_offsets:
                                raw_ptr = _s64(_read_ptr(memory, ops_resolved + offset))
                                init_ptr_info = _resolve_pointer_at(ops_resolved + offset, raw_ptr, fixups_map, memory)
                                init_entries.append(
                                    {
                                        "offset": offset,
                                        "ptr": init_ptr_info,
                                        "owner_entry": _find_entry(entries, init_ptr_info.get("resolved")),
                                    }
                                )
                            mpc_fields["mpo_policy_init"] = init_entries

            ops_reconstructed = None
            ops_reconstructed_owner = None
            if reconstructed and rec_fields:
                ops_field = rec_fields.get("mpc_ops") or {}
                store_value = ops_field.get("store_value") or {}
                expr = store_value.get("symbolic_expr") or store_value.get("resolution") or {}
                ops_base_reg = expr.get("base_reg")
                ops_base_offset = expr.get("delta")
                if ops_base_reg and ops_base_offset is not None:
                    ops_reconstructed = _recover_ops_from_stores(
                        instr,
                        ops_base_reg,
                        ops_base_offset,
                        memory,
                        fixups_map,
                        entries,
                        max_back=max_back * 4,
                    )
                    if ops_reconstructed:
                        hist = {}
                        exec_ptrs = 0
                        for entry in ops_reconstructed:
                            resolved_val = entry.get("resolved_value")
                            if resolved_val is None:
                                continue
                            if not _is_exec_addr(memory, resolved_val):
                                continue
                            exec_ptrs += 1
                            owner = entry.get("owner_entry")
                            if owner:
                                hist[owner] = hist.get(owner, 0) + 1
                        if hist:
                            ops_reconstructed_owner = max(hist.items(), key=lambda item: item[1])[0]
                        if mpc_fields and mpc_fields.get("mpc_ops_owner") is None:
                            mpc_fields["mpc_ops_owner"] = ops_reconstructed_owner

            ops_resolved = None
            if mpc_fields:
                ops_resolved = (mpc_fields.get("mpc_ops_ptr") or {}).get("resolved")
            if ops_resolved is not None:
                hist = _ops_owner_histogram(ops_resolved, memory, entries, fixups_map)
                mpc_fields["ops_owner_histogram"] = hist
                mpc_fields["mpc_ops_owner"] = hist.get("owner_top") if hist else None

            caller_entry = _find_entry(entries, _s64(call_addr_val))

            results.append(
                {
                    "call_site": {
                        "address": _format_addr(call_addr_val),
                        "mnemonic": instr.getMnemonicString(),
                        "caller_function": {
                            "name": caller_func.getName() if caller_func else None,
                            "entry": _format_addr(_s64(caller_func.getEntryPoint().getOffset())) if caller_func else None,
                        },
                        "caller_fileset_entry": caller_entry,
                    },
                    "mpc_resolution": mpc_resolution,
                    "arg_resolution": attempts,
                    "mpc": mpc_fields,
                    "mpc_reconstructed": reconstructed,
                    "ops_reconstructed": ops_reconstructed,
                    "ops_reconstructed_owner": ops_reconstructed_owner,
                }
            )

        out = {
            "meta": {
                "build_id": build_id,
                "program": currentProgram.getName(),
                "call_sites_path": call_sites_path,
                "fixups_path": fixups_path,
                "fileset_index_path": fileset_index_path,
                "mac_policy_register": {
                    "address": _format_addr(_s64(_parse_hex(mac_policy_register_addr))) if mac_policy_register_addr else None,
                    "name": mac_policy_func.getName() if mac_policy_func else None,
                    "mpo_policy_init_offsets": mpo_policy_init_offsets,
                },
                "scan_limits": {"max_back": max_back},
            },
            "instances": results,
        }

        with open(os.path.join(out_dir, "mac_policy_register_instances.json"), "w") as fh:
            json.dump(out, fh, indent=2, sort_keys=True)
        print("kernel_mac_policy_register_instances: wrote %d instances" % len(results))
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
