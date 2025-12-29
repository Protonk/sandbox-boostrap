"""Helpers for node/struct scans in sandbox Ghidra scripts.

This module implements lightweight expression tracking and pcode filtering so
struct-field scans can stay in Python/Jython. The API is tuned for determinism
over completeness: we prefer predictable JSON output to fragile decompiler state.
"""

import re
from collections import Counter
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.address import AddressSpace
from ghidra.program.model.lang import Register


# Bump when JSON output format changes so downstream snapshots can track it.
SCHEMA_VERSION = "1.0"


class Expr(object):
    # Expr tracks a linear expression: sum(coeff*var) + const, or unknown.
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


def get_reg_name(varnode, program):
    try:
        reg = program.getRegister(varnode.getAddress(), varnode.getSize())
        if isinstance(reg, Register):
            name = reg.getName().upper()
            if name.startswith("W") and name[1:].isdigit():
                return "X" + name[1:]
            return name
    except Exception:
        pass
    return None


def eval_varnode(varnode, defs, program, reg_env=None, depth=0):
    if varnode is None or depth > 25:
        # Depth cap keeps recursive pcode resolution from exploding on cyclic defs.
        return Expr(unknown=True)
    space = varnode.getAddress().getAddressSpace()
    if space.isConstantSpace():
        return Expr(const=varnode.getOffset())
    if space.isRegisterSpace():
        name = get_reg_name(varnode, program) or "reg_%x" % varnode.getOffset()
        if reg_env and name in reg_env:
            return reg_env[name].copy()
        return Expr(terms={name: 1})
    if space.getType() == AddressSpace.TYPE_UNIQUE:
        # UNIQUE space nodes are Ghidra temporaries; chase their defining pcode op.
        defining = defs.get(varnode)
        if defining is None:
            return Expr(unknown=True)
        opc = defining.getOpcode()
        if opc in (
            PcodeOp.COPY,
            PcodeOp.INT_ZEXT,
            PcodeOp.INT_SEXT,
            PcodeOp.CAST,
            PcodeOp.PTRSUB,
            PcodeOp.SUBPIECE,
        ):
            return eval_varnode(defining.getInput(0), defs, program, reg_env, depth + 1)
        if opc == PcodeOp.INT_2COMP:
            inner = eval_varnode(defining.getInput(0), defs, program, reg_env, depth + 1)
            return inner.scale(-1)
        if opc in (PcodeOp.INT_ADD, PcodeOp.PTRADD):
            a = eval_varnode(defining.getInput(0), defs, program, reg_env, depth + 1)
            b = eval_varnode(defining.getInput(1), defs, program, reg_env, depth + 1)
            return a.add(b)
        if opc == PcodeOp.INT_SUB:
            a = eval_varnode(defining.getInput(0), defs, program, reg_env, depth + 1)
            b = eval_varnode(defining.getInput(1), defs, program, reg_env, depth + 1)
            return a.add(b.scale(-1))
        if opc == PcodeOp.INT_LEFT:
            base = eval_varnode(defining.getInput(0), defs, program, reg_env, depth + 1)
            shift = eval_varnode(defining.getInput(1), defs, program, reg_env, depth + 1)
            if shift.unknown or shift.terms:
                return Expr(unknown=True)
            return base.scale(1 << shift.const)
        if opc == PcodeOp.INT_MULT:
            a = eval_varnode(defining.getInput(0), defs, program, reg_env, depth + 1)
            b = eval_varnode(defining.getInput(1), defs, program, reg_env, depth + 1)
            if not a.unknown and not b.unknown:
                if len(a.terms) == 0:
                    return b.scale(a.const)
                if len(b.terms) == 0:
                    return a.scale(b.const)
            return Expr(unknown=True)
        if opc == PcodeOp.PIECE:
            low = eval_varnode(defining.getInput(0), defs, program, reg_env, depth + 1)
            high = eval_varnode(defining.getInput(1), defs, program, reg_env, depth + 1)
            if not high.unknown and len(high.terms) == 0 and high.const == 0:
                return low
    return Expr(unknown=True)


def record_aliases(pcodes, defs, program, reg_env):
    for op in pcodes:
        out = op.getOutput()
        if out is None:
            continue
        space = out.getAddress().getAddressSpace()
        if not space.isRegisterSpace():
            continue
        dest_name = get_reg_name(out, program)
        if dest_name is None:
            continue
        opc = op.getOpcode()
        val = None
        if opc in (PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.CAST):
            val = eval_varnode(op.getInput(0), defs, program, reg_env)
        elif opc in (PcodeOp.INT_ADD, PcodeOp.PTRADD):
            a = eval_varnode(op.getInput(0), defs, program, reg_env)
            b = eval_varnode(op.getInput(1), defs, program, reg_env)
            val = a.add(b)
        elif opc == PcodeOp.INT_SUB:
            a = eval_varnode(op.getInput(0), defs, program, reg_env)
            b = eval_varnode(op.getInput(1), defs, program, reg_env)
            val = a.add(b.scale(-1))
        if val is not None and not val.unknown:
            reg_env[dest_name] = val


def collect_loads(func, program, index_hint=None):
    listing = program.getListing()
    instr_iter = listing.getInstructions(func.getBody(), True)
    load_records = []
    reg_env = {}
    for instr in instr_iter:
        pcodes = instr.getPcode()
        defs = {}
        for op in pcodes:
            out = op.getOutput()
            if out is not None and out not in defs:
                defs[out] = op
        for op in pcodes:
            if op.getOpcode() != PcodeOp.LOAD:
                continue
            addr_v = op.getInput(1)
            expr = eval_varnode(addr_v, defs, program, reg_env)
            out = op.getOutput()
            size = out.getSize() if out is not None else 0
            dest_reg = None
            try:
                objs0 = instr.getOpObjects(0)
                for o in objs0:
                    if isinstance(o, Register):
                        dest_reg = o.getName().upper()
                        break
            except Exception:
                dest_reg = None
            load_records.append(
                {
                    "addr": str(instr.getAddress()),
                    "dest": dest_reg,
                    "width": size,
                    "expr": expr,
                    "expr_str": repr(expr),
                    "disasm": instr.toString(),
                    "mnemonic": instr.getMnemonicString().lower(),
                }
            )
        record_aliases(pcodes, defs, program, reg_env)
    return load_records


def choose_index_and_base(load_records):
    reg_hits = Counter()
    for r in load_records:
        expr = r["expr"]
        if expr.unknown or not expr.terms:
            continue
        for reg, coeff in expr.terms.items():
            if reg.startswith(("SP", "FP")) or reg.startswith("XZR"):
                continue
            if abs(coeff) in (1, 2, 4, 8):
                reg_hits[(reg, coeff)] += 1
    if not reg_hits:
        return None, None, None
    (index_reg, stride), _ = reg_hits.most_common(1)[0]

    bases = Counter()
    for r in load_records:
        expr = r["expr"]
        if expr.unknown or index_reg not in expr.terms:
            continue
        if expr.terms.get(index_reg) != stride:
            continue
        for reg, coeff in expr.terms.items():
            if reg == index_reg:
                continue
            if coeff == 1:
                bases[reg] += 1
    base_reg = bases.most_common(1)[0][0] if bases else None
    return index_reg, stride, base_reg


def filter_loads(load_records, base_reg, index_reg, stride):
    filtered = []
    for r in load_records:
        expr = r["expr"]
        if expr.unknown:
            continue
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
                "mnemonic": r["mnemonic"],
                "disasm": r["disasm"],
            }
        )
    filtered.sort(key=lambda x: (x["offset"], x["disasm"]))
    return filtered


def analyze_usage(func, loads):
    reg_by_offset = {}
    for l in loads:
        if l["dest"] is not None:
            reg_by_offset.setdefault(l["dest"], set()).add(l["offset"])
    interesting = []
    listing = func.getProgram().getListing()
    for instr in listing.getInstructions(func.getBody(), True):
        mnemonic = instr.getMnemonicString().lower()
        text = instr.toString()
        regs = []
        for idx in range(instr.getNumOperands()):
            try:
                for obj in instr.getOpObjects(idx):
                    if isinstance(obj, Register):
                        regs.append(obj.getName().upper())
            except Exception:
                continue
        flags = []
        imm = None
        if mnemonic in ("and", "ands", "tst"):
            m = re.search(r"#0x([0-9a-fA-F]+)", text)
            if m:
                try:
                    imm = int(m.group(1), 16)
                except Exception:
                    imm = None
        if mnemonic in ("tbz", "tbnz", "ubfx", "lsr", "lsrs", "asr", "lsls"):
            flags.append(mnemonic)
        if mnemonic in ("and", "ands", "tst") and imm is not None and imm != 0xFFFF:
            flags.append("%s imm=0x%x" % (mnemonic, imm))
        if mnemonic == "add" and "uxtw" in text.lower():
            flags.append("index_add")
        if not flags:
            continue
        for r in regs:
            if r in reg_by_offset:
                interesting.append(
                    {
                        "insn": str(instr.getAddress()),
                        "disasm": text,
                        "reg": r,
                        "flags": flags,
                    }
                )
    return interesting


def block_name(func):
    try:
        block = func.getProgram().getMemory().getBlock(func.getEntryPoint())
        if block:
            return block.getName()
    except Exception:
        pass
    return None


def validate_candidate_schema(cand):
    required = [
        "function",
        "entry",
        "index_reg",
        "stride",
        "base_reg",
        "byte_offsets",
        "half_offsets",
        "loads",
        "usage",
        "instruction_count",
    ]
    for k in required:
        if k not in cand:
            return False
    return True
