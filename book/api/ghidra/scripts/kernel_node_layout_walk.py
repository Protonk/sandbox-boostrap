#@category Sandbox
"""
Extended node layout hunter:

Modes:
  1) eval_callees <out_dir> [eval_fn_or_addr]
     - Walk call sites in _eval (default fffffe000b40d698) and run a node-layout
       probe on each callee. Outputs: <out_dir>/eval_callees/<func>.{txt,json}.
  2) scan_structs <out_txt> [out_json]
     - Global scan for functions that load >=2 halfwords and >=1 byte from the
       same base+index pattern (likely node-like structs). Outputs a candidate list.
  3) probe <out_txt> [out_json] [target_fn_or_addr] [index_reg]
     - Same behavior as kernel_node_layout_probe.py (single-function probe).

Notes:
- This script leans on pcode heuristics; treat results as leads, not proofs.
- The eval-callees mode is tuned to the Sonoma _eval call graph.
"""

import json
import os
import re
from collections import Counter, defaultdict
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.address import AddressSet, AddressSpace
from ghidra.program.model.lang import Register
from ghidra.program.model.scalar import Scalar

# Default eval address matches the Sonoma KC; override when probing other hosts.
DEFAULT_EVAL = "fffffe000b40d698"


class Expr(object):
    # Expr tracks linear forms used to infer base+index addressing.
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
            if name.startswith("W") and name[1:].isdigit():
                return "X" + name[1:]
            return name
    except Exception:
        pass
    return None


def eval_varnode(varnode, defs, currentProgram, reg_env=None, depth=0, index_hint=None):
    if varnode is None or depth > 25:
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
        if opc in (
            PcodeOp.COPY,
            PcodeOp.INT_ZEXT,
            PcodeOp.INT_SEXT,
            PcodeOp.CAST,
            PcodeOp.PTRSUB,
            PcodeOp.SUBPIECE,
        ):
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
            if out is not None and out not in defs:
                defs[out] = op
        for op in pcodes:
            if op.getOpcode() != PcodeOp.LOAD:
                continue
            addr_v = op.getInput(1)
            expr = eval_varnode(addr_v, defs, currentProgram, reg_env, index_hint=index_hint)
            expr_source = "pcode"
            attempts = []
            if index_hint:
                attempts.append("index_hint")
                # operand fallback
                try:
                    objs = instr.getOpObjects(1)
                except Exception:
                    objs = []
                regs = [o for o in objs if isinstance(o, Register)]
                reg_names = [r.getName().upper() for r in regs]
                if index_hint in reg_names:
                    scalars = [o for o in objs if isinstance(o, Scalar)]
                    expr2 = Expr(terms={index_hint: 1})
                    for name in reg_names:
                        if name == index_hint:
                            continue
                        expr2.terms[name] = expr2.terms.get(name, 0) + 1
                    if scalars:
                        try:
                            expr2.const = int(scalars[0].getValue())
                        except Exception:
                            pass
                    expr = expr2
                    expr_source = "operands"
                    attempts.append("operands_used")
                else:
                    attempts.append("operands_none")
                # disasm fallback
                lower = instr.toString().lower()
                if index_hint.lower() in lower:
                    m = re.search(r"\[(x\d+),\s*(x\d+)", lower)
                    if m:
                        a, b = m.group(1).upper(), m.group(2).upper()
                        base = a
                        idx = b
                        if idx != index_hint and base == index_hint:
                            base, idx = idx, base
                        if idx == index_hint:
                            expr3 = Expr(terms={index_hint: 1})
                            if base != index_hint:
                                expr3.terms[base] = expr3.terms.get(base, 0) + 1
                            m_off = re.search(r"#0x([0-9a-f]+)", lower)
                            if m_off:
                                try:
                                    expr3.const = int(m_off.group(1), 16)
                                except Exception:
                                    pass
                            expr = expr3
                            expr_source = "disasm"
                            attempts.append("disasm_used")
                        else:
                            attempts.append("disasm_none")
                else:
                    attempts.append("disasm_none")

            out = op.getOutput()
            size = out.getSize() if out is not None else 0
            dest_reg = None
            try:
                objs0 = instr.getOpObjects(0)
                for o in objs0:
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

    reg_hits = Counter()
    for r in load_records:
        expr = r["expr"]
        if expr.unknown or not expr.terms:
            continue
        for reg, coeff in expr.terms.items():
            if reg.startswith("SP") or reg.startswith("FP") or reg.startswith("XZR"):
                continue
            if abs(coeff) in (1, 2, 4, 8):
                reg_hits[(reg, coeff)] += 1
    if reg_hits:
        (reg, stride), _ = reg_hits.most_common(1)[0]
        return reg, stride

    return None, None


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


def filter_node_loads(load_records, index_reg, base_reg, stride):
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
    return filtered


def ensure_function(entry, name="auto"):
    func = getFunctionAt(entry)
    if func is None:
        try:
            func = createFunction(entry, name)
            func.setBody(AddressSet(entry, entry.add(0x1000)))
        except Exception:
            func = getFunctionAt(entry)
    return func


def parse_target(arg):
    if arg is None or arg == "":
        return toAddr(DEFAULT_EVAL), None
    try:
        addr = toAddr(arg)
        return addr, None
    except Exception:
        funcs = getGlobalFunctions(arg)
        if funcs:
            return funcs[0].getEntryPoint(), funcs[0]
    return None, None


def probe_function(func, forced_index=None, label=None):
    load_records, instr_count = collect_loads(func, index_hint=forced_index)
    index_reg, stride = choose_index(load_records, forced_index)
    base_reg = None
    if index_reg:
        base_reg = choose_base(load_records, index_reg, stride)
    filtered = filter_node_loads(load_records, index_reg, base_reg, stride)
    return {
        "function": label or func.getName(),
        "entry": str(func.getEntryPoint()),
        "instruction_count": instr_count,
        "index_reg": index_reg,
        "node_stride": stride,
        "node_base": base_reg,
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


def write_probe(out_txt, out_json, result):
    lines = []
    lines.append("== Node layout probe ==")
    lines.append("Function: %s (%s)" % (result["function"], result["entry"]))
    lines.append("Instruction count: %d" % result["instruction_count"])
    lines.append("Index register: %s" % (result["index_reg"] or "unknown"))
    lines.append(
        "Node stride (heuristic): %s"
        % ("0x%x" % result["node_stride"] if result["node_stride"] else "unknown")
    )
    lines.append("Node base register: %s" % (result["node_base"] or "unknown"))
    lines.append("Loads from node pointer (offset, width, dest, insn, expr):")
    for row in result["loads"]:
        lines.append(
            "  offset {:#x}, width {}, dest {}, insn {}, expr {}".format(
                row["offset"], row["width"], row["dest"], row["disasm"], row["expr"]
            )
        )
    lines.append("")
    out_dir = os.path.dirname(out_txt)
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    with open(out_txt, "w") as fh:
        fh.write("\n".join(lines))
    if out_json:
        with open(out_json, "w") as fh:
            json.dump(result, fh, indent=2)


def get_callees(func):
    callees = set()
    listing = currentProgram.getListing()
    instr_iter = listing.getInstructions(func.getBody(), True)
    for ins in instr_iter:
        try:
            ft = ins.getFlowType()
            if ft is None or not ft.isCall():
                continue
            flows = ins.getFlows()
            for dest in flows:
                f = getFunctionAt(dest)
                if f:
                    callees.add(f)
        except Exception:
            continue
    return list(callees)


def heuristic_index_from_loads(load_records):
    reg_hits = Counter()
    for r in load_records:
        expr = r["expr"]
        if expr.unknown or not expr.terms:
            continue
        for reg, coeff in expr.terms.items():
            if reg.startswith("SP") or reg.startswith("FP") or reg.startswith("XZR"):
                continue
            if abs(coeff) in (1, 2, 4, 8):
                reg_hits[(reg, coeff)] += 1
    if reg_hits:
        (reg, stride), _ = reg_hits.most_common(1)[0]
        return reg, stride
    return None, None


def mode_eval_callees(args):
    if len(args) < 2:
        printerr("Usage: eval_callees <out_dir> [eval_fn_or_addr]")
        return
    out_dir = args[1]
    target = args[2] if len(args) > 2 else None
    entry, func = parse_target(target)
    if entry is None:
        printerr("Could not resolve eval target")
        return
    func = func or ensure_function(entry, "auto_eval")
    if func is None:
        printerr("Eval function not found")
        return
    callees = get_callees(func)
    summary = []
    for callee in callees:
        res = probe_function(callee, forced_index=None, label=callee.getName())
        if (not res["index_reg"]) or (not res["loads"]):
            idx, _ = heuristic_index_from_loads(
                [r for r in collect_loads(callee, index_hint=None)[0]]
            )
            if idx:
                res = probe_function(callee, forced_index=idx, label=callee.getName())
        name_safe = callee.getName().replace("/", "_")
        base = os.path.join(out_dir, "eval_callees")
        if not os.path.isdir(base):
            os.makedirs(base)
        txt_path = os.path.join(base, "%s.txt" % name_safe)
        json_path = os.path.join(base, "%s.json" % name_safe)
        write_probe(txt_path, json_path, res)
        summary.append(
            {
                "name": callee.getName(),
                "entry": str(callee.getEntryPoint()),
                "index_reg": res["index_reg"],
                "node_stride": res["node_stride"],
                "node_base": res["node_base"],
                "load_count": len(res["loads"]),
                "out_txt": txt_path,
            }
        )
    summary_path = os.path.join(out_dir, "eval_callees", "summary.json")
    with open(summary_path, "w") as fh:
        json.dump(summary, fh, indent=2)
    print("[+] wrote eval callee reports to %s" % os.path.join(out_dir, "eval_callees"))


def mode_scan_structs(args):
    if len(args) < 2:
        printerr("Usage: scan_structs <out_txt> [out_json]")
        return
    out_txt = args[1]
    out_json = args[2] if len(args) > 2 and args[2] else None
    func_mgr = currentProgram.getFunctionManager()
    funcs = list(func_mgr.getFunctions(True))
    candidates = []
    for func in funcs:
        load_records, _ = collect_loads(func, index_hint=None)
        pattern_map = defaultdict(lambda: defaultdict(list))
        for r in load_records:
            expr = r["expr"]
            if expr.unknown or not expr.terms:
                continue
            bases = [reg for reg, coeff in expr.terms.items() if coeff == 1]
            idxs = [(reg, coeff) for reg, coeff in expr.terms.items() if abs(coeff) in (1, 2, 4, 8)]
            if not bases or not idxs:
                continue
            for base in bases:
                for idx_reg, coeff in idxs:
                    if idx_reg == base:
                        continue
                    key = (base, idx_reg, coeff)
                    pattern_map[key][r["width"]].append(r["expr"].const)
        for key, widths in pattern_map.items():
            halfs = set(widths.get(2, []))
            bytes_ = set(widths.get(1, []))
            if len(halfs) >= 2 and len(bytes_) >= 1:
                base, idx_reg, coeff = key
                candidates.append(
                    {
                        "function": func.getName(),
                        "entry": str(func.getEntryPoint()),
                        "base": base,
                        "index": idx_reg,
                        "stride": coeff,
                        "half_offsets": sorted(list(halfs)),
                        "byte_offsets": sorted(list(bytes_)),
                    }
                )
    candidates.sort(key=lambda c: (-len(c["half_offsets"]), c["function"]))
    lines = []
    lines.append("== Node struct candidates (>=2 ldrh + >=1 ldrb) ==")
    for cand in candidates:
        lines.append(
            "%s (%s): base=%s index=%s stride=%s halfs=%s bytes=%s"
            % (
                cand["function"],
                cand["entry"],
                cand["base"],
                cand["index"],
                hex(cand["stride"]),
                [hex(x) for x in cand["half_offsets"]],
                [hex(x) for x in cand["byte_offsets"]],
            )
        )
    out_dir = os.path.dirname(out_txt)
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    with open(out_txt, "w") as fh:
        fh.write("\n".join(lines))
    if out_json:
        with open(out_json, "w") as fh:
            json.dump(candidates, fh, indent=2)
    print("[+] wrote struct candidates to %s" % out_txt)


def mode_probe(args):
    if len(args) < 2:
        printerr("Usage: probe <out_txt> [out_json] [target] [index_reg]")
        return
    out_txt = args[1]
    out_json = args[2] if len(args) > 2 and args[2] else None
    target_arg = args[3] if len(args) > 3 else None
    forced_index = args[4] if len(args) > 4 else None
    entry, func = parse_target(target_arg)
    if entry is None:
        printerr("Could not resolve target")
        return
    func = func or ensure_function(entry, "auto_target")
    if func is None:
        printerr("Target function not found")
        return
    try:
        for offs in range(0, 0x1000, 4):
            disassemble(entry.add(offs))
    except Exception:
        pass
    res = probe_function(func, forced_index=forced_index, label=func.getName())
    write_probe(out_txt, out_json, res)


def run():
    args = getScriptArgs()
    if not args:
        printerr("Usage: kernel_node_layout_walk.py <mode> ...")
        return
    mode = args[0]
    if mode == "eval_callees":
        mode_eval_callees(args)
    elif mode == "scan_structs":
        mode_scan_structs(args)
    elif mode == "probe":
        mode_probe(args)
    else:
        # backward-compatible default: treat first arg as out_txt
        mode_probe(["probe"] + list(args))


run()
