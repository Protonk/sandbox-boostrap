#@category Sandbox
"""
Probe memory access patterns in a target function to recover a node-like
layout (base + indexed cursor) and any likely field offsets.

Usage (script args):
  <out_txt> [out_json] [target_fn_or_addr] [index_reg]

Defaults:
  target_fn_or_addr: fffffe000b40d698 (_eval)
  index_reg: guess from loads (or X22 if not found)

Notes:
- This probe uses pcode to approximate index/base arithmetic; it is heuristic by design.
- Ghidra decompiler output can vary across versions, so keep results as hints.
"""

import json
import os
import re
from collections import Counter
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.address import AddressSet, AddressSpace
from ghidra.program.model.lang import Register
from ghidra.program.model.scalar import Scalar

# Default target is _eval in the Sonoma KC; override when probing other layouts.
DEFAULT_TARGET = "fffffe000b40d698"


class Expr(object):
    # Expr tracks linear combinations of registers plus a constant offset.
    def __init__(self, terms=None, const=0, unknown=False):
        self.terms = terms or {}
        self.const = const
        self.unknown = unknown

    def copy(self):
        return Expr(dict(self.terms), self.const, self.unknown)

    def scale(self, factor):
        e = self.copy()
        for k in e.terms:
            e.terms[k] = e.terms[k] * factor
        e.const *= factor
        return e

    def add(self, other):
        if self.unknown or other.unknown:
            return Expr(unknown=True)
        e = Expr(dict(self.terms), self.const)
        for k, v in other.terms.items():
            e.terms[k] = e.terms.get(k, 0) + v
        e.const += other.const
        return e

    def __repr__(self):
        if self.unknown:
            return "<unknown>"
        parts = []
        for reg, coeff in sorted(self.terms.items()):
            if coeff == 1:
                parts.append(reg)
            else:
                parts.append("%s*%s" % (reg, coeff))
        if self.const:
            parts.append("0x%x" % self.const)
        if not parts:
            return "0"
        return " + ".join(parts)


def get_reg_name(varnode, currentProgram):
    try:
        reg = currentProgram.getRegister(varnode.getAddress(), varnode.getSize())
        if isinstance(reg, Register):
            name = reg.getName().upper()
            # normalize 32-bit GPR names to 64-bit to keep coefficients aligned
            if name.startswith("W") and name[1:].isdigit():
                return "X" + name[1:]
            return name
    except Exception:
        pass
    return None


def eval_varnode(varnode, defs, currentProgram, reg_env=None, depth=0, index_hint=None):
    if varnode is None:
        return Expr(unknown=True)
    if depth > 25:
        return Expr(unknown=True)
    space = varnode.getAddress().getAddressSpace()
    if space.isConstantSpace():
        return Expr(const=varnode.getOffset())
    if space.isRegisterSpace():
        name = get_reg_name(varnode, currentProgram) or "reg_%x" % varnode.getOffset()
        if reg_env and name in reg_env:
            mapped = reg_env[name]
            if (index_hint is None) or (not mapped.unknown and index_hint in mapped.terms):
                return mapped.copy()
        return Expr(terms={name: 1})
    if space.getType() == AddressSpace.TYPE_UNIQUE:
        defining = defs.get(varnode)
        if defining is None:
            return Expr(unknown=True)
        opc = defining.getOpcode()
        if opc in (PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.CAST, PcodeOp.PTRSUB, PcodeOp.SUBPIECE):
            return eval_varnode(defining.getInput(0), defs, currentProgram, reg_env, depth + 1, index_hint)
        if opc == PcodeOp.INT_2COMP:
            inner = eval_varnode(defining.getInput(0), defs, currentProgram, reg_env, depth + 1, index_hint)
            return inner.scale(-1)
        if opc in (PcodeOp.INT_ADD, PcodeOp.PTRADD):
            a = eval_varnode(defining.getInput(0), defs, currentProgram, reg_env, depth + 1, index_hint)
            b = eval_varnode(defining.getInput(1), defs, currentProgram, reg_env, depth + 1, index_hint)
            return a.add(b)
        if opc == PcodeOp.INT_SUB:
            a = eval_varnode(defining.getInput(0), defs, currentProgram, reg_env, depth + 1, index_hint)
            b = eval_varnode(defining.getInput(1), defs, currentProgram, reg_env, depth + 1, index_hint)
            return a.add(b.scale(-1))
        if opc == PcodeOp.INT_LEFT:
            base = eval_varnode(defining.getInput(0), defs, currentProgram, reg_env, depth + 1, index_hint)
            shift = eval_varnode(defining.getInput(1), defs, currentProgram, reg_env, depth + 1, index_hint)
            if shift.unknown or shift.terms:
                return Expr(unknown=True)
            return base.scale(1 << shift.const)
        if opc == PcodeOp.INT_MULT:
            a = eval_varnode(defining.getInput(0), defs, currentProgram, reg_env, depth + 1, index_hint)
            b = eval_varnode(defining.getInput(1), defs, currentProgram, reg_env, depth + 1, index_hint)
            if not a.unknown and not b.unknown:
                if len(a.terms) == 0:
                    return b.scale(a.const)
                if len(b.terms) == 0:
                    return a.scale(b.const)
            return Expr(unknown=True)
        if opc == PcodeOp.PIECE:
            low = eval_varnode(defining.getInput(0), defs, currentProgram, reg_env, depth + 1, index_hint)
            high = eval_varnode(defining.getInput(1), defs, currentProgram, reg_env, depth + 1, index_hint)
            if not high.unknown and len(high.terms) == 0 and high.const == 0:
                return low
    return Expr(unknown=True)


def parse_target(arg):
    if arg is None or arg == "":
        return toAddr(DEFAULT_TARGET), None
    try:
        addr = toAddr(arg)
        return addr, None
    except Exception:
        funcs = getGlobalFunctions(arg)
        if funcs:
            return funcs[0].getEntryPoint(), funcs[0]
    return None, None


def choose_index(load_records, forced_reg=None):
    if forced_reg:
        forced = forced_reg.upper()
        coeffs = Counter()
        for r in load_records:
            if r["expr"].unknown:
                continue
            if forced in r["expr"].terms:
                coeffs[r["expr"].terms[forced]] += 1
        stride = coeffs.most_common(1)[0][0] if coeffs else None
        return forced, stride

    counts = Counter()
    for r in load_records:
        if r["expr"].unknown:
            continue
        if len(r["expr"].terms) == 0:
            continue
        if len(r["expr"].terms) > 3:
            continue
        for reg, coeff in r["expr"].terms.items():
            if abs(coeff) in (1, 2, 4, 8):
                counts[(reg, coeff)] += 1
    if not counts:
        return None, None
    (reg, stride), _ = counts.most_common(1)[0]
    return reg, stride


def choose_base(load_records, index_reg, stride):
    bases = Counter()
    for r in load_records:
        expr = r["expr"]
        if expr.unknown:
            continue
        coeff = expr.terms.get(index_reg)
        if coeff is None or (stride is not None and coeff != stride):
            continue
        for reg, coeff in expr.terms.items():
            if reg == index_reg:
                continue
            if coeff == 1:
                bases[reg] += 1
    if not bases:
        return None
    return bases.most_common(1)[0][0]


def record_aliases(pcodes, defs, currentProgram, reg_env, index_hint=None):
    for op in pcodes:
        out = op.getOutput()
        if out is None:
            continue
        space = out.getAddress().getAddressSpace()
        if not space.isRegisterSpace():
            continue
        dest_name = get_reg_name(out, currentProgram)
        if dest_name is None:
            continue
        opc = op.getOpcode()
        val = None
        if opc in (PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.CAST):
            val = eval_varnode(op.getInput(0), defs, currentProgram, reg_env, index_hint=index_hint)
        elif opc in (PcodeOp.INT_ADD, PcodeOp.PTRADD):
            a = eval_varnode(op.getInput(0), defs, currentProgram, reg_env, index_hint=index_hint)
            b = eval_varnode(op.getInput(1), defs, currentProgram, reg_env, index_hint=index_hint)
            val = a.add(b)
        elif opc == PcodeOp.INT_SUB:
            a = eval_varnode(op.getInput(0), defs, currentProgram, reg_env, index_hint=index_hint)
            b = eval_varnode(op.getInput(1), defs, currentProgram, reg_env, index_hint=index_hint)
            val = a.add(b.scale(-1))
        if val is not None and not val.unknown:
            reg_env[dest_name] = val


def collect_loads(func, index_hint=None):
    def fallback_operand_expr(instr, index_hint):
        try:
            objs = instr.getOpObjects(1)
        except Exception:
            return None
        regs = [o for o in objs if isinstance(o, Register)]
        reg_names = [r.getName().upper() for r in regs]
        if index_hint not in reg_names:
            return None
        scalars = [o for o in objs if isinstance(o, Scalar)]
        expr = Expr(terms={index_hint: 1})
        for name in reg_names:
            if name == index_hint:
                continue
            expr.terms[name] = expr.terms.get(name, 0) + 1
        if scalars:
            try:
                expr.const = int(scalars[0].getValue())
            except Exception:
                pass
        return expr

    def fallback_disasm_expr(disasm, index_hint):
        lower = disasm.lower()
        hint = index_hint.lower()
        if hint not in lower:
            return None
        m = re.search(r"\[(x\d+),\s*(x\d+)", lower)
        if not m:
            return None
        a, b = m.group(1).upper(), m.group(2).upper()
        base = a
        idx = b
        if idx != index_hint and base == index_hint:
            base, idx = idx, base
        if idx != index_hint:
            return None
        expr = Expr(terms={index_hint: 1})
        if base != index_hint:
            expr.terms[base] = expr.terms.get(base, 0) + 1
        m_off = re.search(r"#0x([0-9a-f]+)", lower)
        if m_off:
            try:
                expr.const = int(m_off.group(1), 16)
            except Exception:
                pass
        return expr

    listing = currentProgram.getListing()
    instr_iter = listing.getInstructions(func.getBody(), True)
    load_records = []
    reg_env = {}
    instr_count = 0
    for instr in instr_iter:
        instr_count += 1
        pcodes = instr.getPcode()
        defs = {}
        for op in pcodes:
            out = op.getOutput()
            if out is not None:
                if out in defs:
                    continue
                defs[out] = op
        for op in pcodes:
            if op.getOpcode() == PcodeOp.LOAD:
                addr_v = op.getInput(1)
                expr = eval_varnode(addr_v, defs, currentProgram, reg_env, index_hint=index_hint)
                expr_source = "pcode"
                attempts = []
                if index_hint:
                    attempts.append("index_hint")
                    fb = fallback_operand_expr(instr, index_hint)
                    if fb and index_hint in fb.terms:
                        expr = fb
                        expr_source = "operands"
                        attempts.append("operands_used")
                    else:
                        attempts.append("operands_none")
                    fb2 = fallback_disasm_expr(instr.toString(), index_hint)
                    if fb2 and index_hint in fb2.terms:
                        expr = fb2
                        expr_source = "disasm"
                        attempts.append("disasm_used")
                    else:
                        attempts.append("disasm_none")
                out = op.getOutput()
                size = out.getSize() if out is not None else 0
                dest_reg = None
                try:
                    objs = instr.getOpObjects(0)
                    for o in objs:
                        if isinstance(o, Register):
                            dest_reg = o.getName()
                            break
                except Exception:
                    dest_reg = None
                load_records.append(
                    {
                        "addr": str(instr.getAddress()),
                        "insn_addr": str(instr.getAddress()),
                        "dest": dest_reg,
                        "width": size,
                        "expr": expr,
                        "expr_str": repr(expr),
                        "expr_source": expr_source,
                        "attempts": attempts,
                        "disasm": instr.toString(),
                    }
                )
        record_aliases(pcodes, defs, currentProgram, reg_env, index_hint=index_hint)
    return load_records, instr_count


def run():
    args = getScriptArgs()
    if len(args) < 1:
        printerr("Usage: kernel_node_layout_probe.py <out_txt> [out_json] [target_fn_or_addr] [index_reg]")
        return
    out_txt = args[0]
    out_json = args[1] if len(args) > 1 and args[1] else None
    target_arg = args[2] if len(args) > 2 else None
    forced_index = args[3] if len(args) > 3 and args[3] else None

    entry, func = parse_target(target_arg)
    if entry is None:
        printerr("Could not resolve target %s" % (target_arg or DEFAULT_TARGET))
        return
    if func is None:
        func = getFunctionAt(entry)
    if func is None:
        try:
            func = createFunction(entry, "auto_target")
            func.setBody(AddressSet(entry, entry.add(0x1000)))
        except Exception:
            func = getFunctionAt(entry)
    if func is None:
        printerr("Function not found at %s" % entry)
        return

    try:
        for offs in range(0, 0x1000, 4):
            disassemble(entry.add(offs))
    except Exception:
        pass

    load_records, instr_count = collect_loads(func, index_hint=forced_index)
    index_reg, stride = choose_index(load_records, forced_index)
    base_reg = None
    if index_reg:
        base_reg = choose_base(load_records, index_reg, stride)

    filtered = []
    for r in load_records:
        expr = r["expr"]
        if expr.unknown:
            continue
        if index_reg:
            coeff = expr.terms.get(index_reg)
            if coeff is None:
                continue
            if stride is not None and coeff != stride:
                continue
        if base_reg and expr.terms.get(base_reg, 0) != 1:
            continue
        filtered.append(
            {
                "offset": expr.const,
                "width": r["width"],
                "dest": r["dest"],
                "insn_addr": r["insn_addr"],
                "disasm": r["disasm"],
                "expr": r["expr_str"],
            }
        )
    filtered.sort(key=lambda x: (x["offset"], x["insn_addr"]))

    lines = []
    lines.append("== Node layout probe ==")
    lines.append("Function: %s (%s)" % (func.getName(), func.getEntryPoint()))
    lines.append("Instruction count: %d" % instr_count)
    lines.append("Index register: %s" % (index_reg or "unknown"))
    lines.append("Node stride (heuristic): %s" % ("0x%x" % stride if stride else "unknown"))
    lines.append("Node base register: %s" % (base_reg or "unknown"))
    lines.append("Loads from node pointer (offset, width, dest, insn, expr):")
    for row in filtered:
        lines.append(
            "  offset {:#x}, width {}, dest {}, insn {}, expr {}".format(
                row["offset"], row["width"], row["dest"], row["disasm"], row["expr"]
            )
        )
    lines.append("")

    out_dir = os.path.dirname(out_txt)
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    with open(out_txt, "a") as fh:
        fh.write("\n".join(lines))
    if out_json:
        data = {
            "function": func.getName(),
            "entry": str(func.getEntryPoint()),
            "instruction_count": instr_count,
            "node_stride": stride,
            "node_base": base_reg,
            "index_reg": index_reg,
            "loads": filtered,
            "debug_loads": [
                {
                    "addr": r.get("addr"),
                    "disasm": r["disasm"],
                    "expr": r["expr_str"],
                    "source": r.get("expr_source"),
                    "attempts": r.get("attempts"),
                    "terms": getattr(r.get("expr"), "terms", None),
                }
                for r in load_records
            ],
        }
        with open(out_json, "w") as fh:
            json.dump(data, fh, indent=2)
    print("[+] wrote layout probe for %s" % func.getName())


run()
