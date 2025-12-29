#@category Sandbox
"""
Rename and apply a signature to the mac_policy_register function anchor.

Args: <out_dir> <build_id> <function_addr> [name]
Outputs: <out_dir>/mac_policy_register_anchor.json
"""

import json
import os
import traceback

from ghidra_bootstrap import scan_utils

from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.util.parser import FunctionSignatureParser
from ghidra.program.model.data import (
    CategoryPath,
    DataTypeConflictHandler,
    PointerDataType,
    StructureDataType,
    TypedefDataType,
    VoidDataType,
)
from java.lang import Throwable
from ghidra.program.model.symbol import SourceType

_RUN = False


def _s64(val):
    return scan_utils.to_signed(val)


def _parse_hex(text):
    return scan_utils.parse_signed_hex(text)


def _ensure_out_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def run():
    global _RUN
    if _RUN:
        return
    _RUN = True
    out_dir = None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_anchor_mac_policy_register.py <out_dir> <build_id> <function_addr> [name]")
            return
        out_dir = args[0]
        build_id = args[1]
        addr_text = args[2]
        name = args[3] if len(args) > 3 else "mac_policy_register"

        _ensure_out_dir(out_dir)
        addr_val = _parse_hex(addr_text)
        if addr_val is None:
            raise ValueError("Invalid address: %s" % addr_text)
        addr = toAddr(_s64(addr_val))
        func = getFunctionAt(addr)
        if not func:
            func = createFunction(addr, name)
        if func:
            func.setName(name, SourceType.USER_DEFINED)

        signature_text = "int %s(struct mac_policy_conf *mpc, mac_policy_handle_t *handlep, void *xd)" % name
        fallback_signature = "int %s(mac_policy_conf *mpc, mac_policy_handle_t *handlep, void *xd)" % name
        sig_result = {
            "signature": signature_text,
            "fallback_signature": fallback_signature,
            "applied": False,
            "error": None,
        }
        if func:
            try:
                dtm = currentProgram.getDataTypeManager()
                cat = CategoryPath("/")
                conf = dtm.getDataType(cat, "mac_policy_conf")
                if conf is None:
                    conf = StructureDataType(cat, "mac_policy_conf", 0)
                    dtm.addDataType(conf, DataTypeConflictHandler.KEEP_HANDLER)
                handle = dtm.getDataType(cat, "mac_policy_handle_t")
                if handle is None:
                    handle = TypedefDataType(cat, "mac_policy_handle_t", PointerDataType(VoidDataType.dataType))
                    dtm.addDataType(handle, DataTypeConflictHandler.KEEP_HANDLER)
                parser = FunctionSignatureParser(currentProgram.getDataTypeManager(), None)
                sig = None
                try:
                    sig = parser.parse(None, signature_text)
                except Throwable:
                    sig = parser.parse(None, fallback_signature)
                    sig_result["signature"] = fallback_signature
                cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(), sig, SourceType.USER_DEFINED)
                sig_result["applied"] = cmd.applyTo(currentProgram)
                if not sig_result["applied"]:
                    sig_result["error"] = "ApplyFunctionSignatureCmd returned false"
            except Throwable as exc:
                sig_result["error"] = str(exc)

        out = {
            "meta": {
                "build_id": build_id,
                "program": currentProgram.getName(),
            },
            "anchor": {
                "address": scan_utils.format_address(addr.getOffset()),
                "name": name,
                "function": func.getName() if func else None,
                "signature": sig_result,
            },
        }
        with open(os.path.join(out_dir, "mac_policy_register_anchor.json"), "w") as f:
            json.dump(out, f, indent=2, sort_keys=True)
        print("kernel_anchor_mac_policy_register: wrote anchor record")
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
