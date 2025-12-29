#@category Sandbox
"""
Import BootKernelExtensions.kc, focus on com.apple.security.sandbox blocks, and emit symbol/string tables.
Outputs land under dumps/ghidra/out/<build>/kernel-symbols/.

Args (from scaffold): <out_dir> [build_id]
Pitfalls: with --no-analysis you still get symbol tables but fewer functions; block filtering prefers sandbox-named blocks, falls back to full program if unnamed.
"""

import json
import os
import traceback

from ghidra_bootstrap import scan_utils

from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import StringDataInstance
from ghidra.program.model.symbol import SymbolType

_RUN_CALLED = False


def _ensure_out_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def _sandbox_blocks():
    mem = currentProgram.getMemory()
    blocks = []
    for blk in mem.getBlocks():
        name = blk.getName() or ""
        if "sandbox" in name.lower():
            blocks.append(blk)
    if blocks:
        return blocks
    return list(mem.getBlocks())


def _block_set(blocks):
    aset = AddressSet()
    for blk in blocks:
        aset.add(blk.getStart(), blk.getEnd())
    return aset


def _collect_deps(repo_root):
    deps = []
    if not repo_root:
        return deps
    dep_paths = set()
    dep_paths.add(os.path.join("book", "api", "ghidra", "scripts", "ghidra_bootstrap.py"))
    ghidra_lib_dir = os.path.join(repo_root, "book", "api", "ghidra", "ghidra_lib")
    if os.path.isdir(ghidra_lib_dir):
        for root, dirs, files in os.walk(ghidra_lib_dir):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in files:
                if not name.endswith(".py"):
                    continue
                dep_paths.add(os.path.join(root, name))
    for path in sorted(dep_paths):
        dep_abs = path if os.path.isabs(path) else os.path.join(repo_root, path)
        if not os.path.isfile(dep_abs):
            continue
        dep_rel = scan_utils.to_repo_relative(dep_abs, repo_root)
        deps.append({"path": dep_rel, "sha256": scan_utils.sha256_path(dep_abs)})
    return deps


def _read_world_id(repo_root):
    if not repo_root:
        return None
    world_path = os.path.join(repo_root, "book", "world", "sonoma-14.4.1-23E224-arm64", "world.json")
    if not os.path.isfile(world_path):
        return None
    try:
        with open(world_path, "r") as f:
            data = json.load(f)
        return data.get("world_id")
    except Exception:
        return None


def _block_mode(blocks):
    for blk in blocks:
        name = blk.getName() or ""
        if "sandbox" in name.lower():
            return "sandbox"
    return "all"


def _build_provenance(build_id, block_mode, block_count):
    script_path = os.path.realpath(__file__)
    repo_root = scan_utils.find_repo_root(script_path)
    script_rel = scan_utils.to_repo_relative(script_path, repo_root)
    script_sha = scan_utils.sha256_path(script_path)

    deps = _collect_deps(repo_root)

    program_path = None
    program_sha = None
    try:
        program_path = currentProgram.getExecutablePath()
    except Exception:
        program_path = None
    if program_path and os.path.isfile(program_path):
        program_sha = scan_utils.sha256_path(program_path)
    program_rel = scan_utils.to_repo_relative(program_path, repo_root) if program_path else None

    profile_id = os.environ.get("SANDBOX_LORE_GHIDRA_PROFILE_ID")
    if not profile_id:
        profile_id = "kernel_symbols:block_mode=%s:blocks=%d" % (block_mode, block_count)

    return {
        "schema_version": 1,
        "world_id": _read_world_id(repo_root),
        "generator": {
            "script_path": script_rel,
            "script_content_sha256": script_sha,
            "deps": deps,
        },
        "input": {
            "program_path": program_rel,
            "program_sha256": program_sha,
        },
        "analysis": {
            "profile_id": profile_id,
        },
        "build_id": build_id,
    }


def _collect_symbols(address_set):
    symtab = currentProgram.getSymbolTable()
    memory = currentProgram.getMemory()
    iterator = symtab.getSymbolIterator(True)
    out = []
    while iterator.hasNext() and not monitor.isCancelled():
        sym = iterator.next()
        addr = sym.getAddress()
        if address_set and not address_set.contains(addr):
            continue
        block = memory.getBlock(addr)
        entry = {
            "name": sym.getName(),
            "type": sym.getSymbolType().toString(),
            "address": scan_utils.format_address(addr.getOffset()),
            "namespace": sym.getParentNamespace().getName(True),
            "block": block.getName() if block else None,
        }
        if sym.getSymbolType() == SymbolType.FUNCTION:
            func = currentProgram.getFunctionManager().getFunctionAt(addr)
            if func:
                entry["function_size"] = func.getBody().getNumAddresses()
        out.append(entry)
    return out


def _collect_strings(address_set):
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
    data_iter = listing.getDefinedData(True)
    out = []
    while data_iter.hasNext() and not monitor.isCancelled():
        data = data_iter.next()
        addr = data.getAddress()
        if not address_set.contains(addr):
            continue
        if not StringDataInstance.isString(data):
            continue
        sval = data.getValue()
        if sval is None:
            continue
        block = memory.getBlock(addr)
        out.append(
            {
                "address": scan_utils.format_address(addr.getOffset()),
                "value": str(sval),
                "block": block.getName() if block else None,
            }
        )
    return out


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 1:
            print("usage: kernel_symbols.py <out_dir> [build_id]")
            return
        out_dir = args[0]
        build_id = args[1] if len(args) > 1 else ""
        print("kernel_symbols: starting for build %s -> %s" % (build_id, out_dir))

        _ensure_out_dir(out_dir)
        trace_path = os.path.join(out_dir, "trace.log")
        with open(trace_path, "a") as trace:
            trace.write("start\n")

        blocks = _sandbox_blocks()
        addr_set = _block_set(blocks)
        block_meta = [
            {
                "name": blk.getName(),
                "start": scan_utils.format_address(blk.getStart().getOffset()),
                "end": scan_utils.format_address(blk.getEnd().getOffset()),
            }
            for blk in blocks
        ]
        block_mode = _block_mode(blocks)
        provenance = _build_provenance(build_id, block_mode, len(blocks))

        symbols = _collect_symbols(addr_set)
        strings = _collect_strings(addr_set)
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "block_filter": block_meta,
            "symbol_count": len(symbols),
            "string_count": len(strings),
        }

        with open(os.path.join(out_dir, "symbols.json"), "w") as f:
            json.dump({"_provenance": provenance, "meta": meta, "symbols": symbols}, f, indent=2, sort_keys=True)
        with open(os.path.join(out_dir, "strings.json"), "w") as f:
            json.dump({"_provenance": provenance, "meta": meta, "strings": strings}, f, indent=2, sort_keys=True)

        print("kernel_symbols: wrote %d symbols and %d strings to %s" % (len(symbols), len(strings), out_dir))
        with open(trace_path, "a") as trace:
            trace.write("done\n")
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
