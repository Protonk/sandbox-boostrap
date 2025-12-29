#@category Sandbox
"""
Scan instruction text for a specific immediate offset (e.g., #0xc0).
Args: <out_dir> <build_id> <offset_hex> [write] [all]

Options:
  write      - include only store-like mnemonics (str/stur/stp).
  all        - scan all blocks (default scans sandbox-named blocks if present).
  exact      - require exact offset matches (avoid #0xc00 when searching #0xc0).
  canonical  - include canonical u64 address strings in hits.
  classify   - include access classification (load/store/other).
  skip-stack - skip stack-frame accesses ([sp]/[x29]/[fp]).

Outputs: <out_dir>/offset_inst_scan.json
"""

import json
import os
import traceback

from ghidra_bootstrap import scan_utils

from ghidra.program.model.address import AddressSet

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


def _bool_str(value):
    return "true" if value else "false"


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


def _build_provenance(build_id, needle, write_only, scan_all, exact_match, include_canonical, include_access, skip_stack):
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
        profile_id = (
            "kernel_offset_inst_scan:offset=%s:write=%s:all=%s:exact=%s:"
            "canonical=%s:classify=%s:skip_stack=%s"
            % (
                needle,
                _bool_str(write_only),
                _bool_str(scan_all),
                _bool_str(exact_match),
                _bool_str(include_canonical),
                _bool_str(include_access),
                _bool_str(skip_stack),
            )
        )

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


def run():
    global _RUN_CALLED
    if _RUN_CALLED:
        return
    _RUN_CALLED = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_offset_inst_scan.py <out_dir> <build_id> <offset_hex> [write] [all]")
            return
        out_dir = args[0]
        build_id = args[1]
        needle = str(args[2]).lower()
        if not needle.startswith("0x"):
            needle = "0x" + needle
        needle_text = "#" + needle

        write_only = False
        scan_all = False
        exact_match = False
        include_canonical = False
        include_access = False
        skip_stack = False
        for token in args[3:]:
            tok = str(token).lower()
            if tok == "write":
                write_only = True
            elif tok == "all":
                scan_all = True
            elif tok == "exact":
                exact_match = True
            elif tok == "canonical":
                include_canonical = True
            elif tok == "classify":
                include_access = True
            elif tok == "skip-stack":
                skip_stack = True

        _ensure_out_dir(out_dir)
        listing = currentProgram.getListing()
        func_mgr = currentProgram.getFunctionManager()
        blocks = list(currentProgram.getMemory().getBlocks()) if scan_all else _sandbox_blocks()
        addr_set = _block_set(blocks)

        hits = []
        instr_iter = listing.getInstructions(addr_set, True)
        while instr_iter.hasNext() and not monitor.isCancelled():
            instr = instr_iter.next()
            inst_text = str(instr)
            if exact_match:
                if not scan_utils.exact_offset_match(inst_text, needle):
                    continue
            else:
                if needle_text not in inst_text:
                    continue
            if skip_stack and scan_utils.is_stack_access(inst_text):
                continue
            mnemonic = instr.getMnemonicString().lower()
            if write_only and not (mnemonic.startswith("str") or mnemonic.startswith("stur") or mnemonic.startswith("stp")):
                continue
            addr = instr.getAddress()
            func = func_mgr.getFunctionContaining(addr)
            entry = {
                "address": scan_utils.format_address(addr.getOffset()),
                "function": func.getName() if func else None,
                "mnemonic": instr.getMnemonicString(),
                "inst": inst_text,
            }
            if include_canonical:
                entry["address_canon"] = scan_utils.format_address(addr.getOffset())
            if include_access:
                entry["access"] = scan_utils.classify_mnemonic(instr.getMnemonicString())
            entry["stack_access"] = scan_utils.is_stack_access(inst_text)
            hits.append(entry)
        block_meta = [{"name": b.getName(), "start": scan_utils.format_address(b.getStart().getOffset()), "end": scan_utils.format_address(b.getEnd().getOffset())} for b in blocks]
        meta = {
            "build_id": build_id,
            "program": currentProgram.getName(),
            "offset": needle,
            "hit_count": len(hits),
            "write_only": write_only,
            "scan_all_blocks": scan_all,
            "exact_match": exact_match,
            "include_canonical": include_canonical,
            "include_access": include_access,
            "skip_stack": skip_stack,
            "block_filter": block_meta,
        }
        provenance = _build_provenance(
            build_id,
            needle,
            write_only,
            scan_all,
            exact_match,
            include_canonical,
            include_access,
            skip_stack,
        )
        with open(os.path.join(out_dir, "offset_inst_scan.json"), "w") as f:
            json.dump({"meta": meta, "hits": hits, "_provenance": provenance}, f, indent=2, sort_keys=True)
        print("kernel_offset_inst_scan: %d hits for %s" % (len(hits), needle))
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
