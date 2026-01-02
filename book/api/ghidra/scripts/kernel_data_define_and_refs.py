#@category Sandbox
"""
Define data at given addresses and report references.

Args: <out_dir> <build_id> addr:<hex> [addr:<hex> ...]
Outputs: book/evidence/dumps/ghidra/out/<build>/kernel-data-define/data_refs.json (plus script.log)

Behavior/pitfalls:
- Addresses must be prefixed with `addr:` and parsed as unsigned hex; other forms are ignored.
- Defines 8-byte values as QWORDs, then walks xrefs to dump callers and contents.
- Works best against an existing analyzed project (`--process-existing --no-analysis`) after a full import.

Notes:
- Data definitions modify the listing; run in a disposable project when possible.
- Ghidra treats addresses as signed; scan_utils.format_address normalizes output.
"""
import json, os, traceback
from ghidra.program.model.data import DataUtilities, DataTypeConflictHandler
from ghidra.program.model.data import QWordDataType
from ghidra_bootstrap import scan_utils

_RUN = False

def _ensure(path):
    if not os.path.isdir(path):
        os.makedirs(path)

def run():
    global _RUN
    if _RUN:
        return
    _RUN = True
    out_dir=None
    try:
        args = getScriptArgs()
        if len(args) < 3:
            print("usage: kernel_data_define_and_refs.py <out_dir> <build_id> addr:<hex> ...")
            return
        out_dir = args[0]; build_id = args[1]
        targets=[]
        for a in args[2:]:
            s=str(a)
            if s.startswith('addr:'):
                # Require the addr: prefix to avoid accidental decimal parsing.
                targets.append(scan_utils.parse_hex(s.split('addr:',1)[1]))
        _ensure(out_dir)
        listing=currentProgram.getListing()
        dtm=currentProgram.getDataTypeManager()
        qdt = QWordDataType()
        ref_mgr=currentProgram.getReferenceManager()
        func_mgr=currentProgram.getFunctionManager()
        factory=currentProgram.getAddressFactory()
        results=[]
        for t in targets:
            addr=factory.getDefaultAddressSpace().getAddress(scan_utils.format_address(t))
            # Define a QWORD to coerce Ghidra into creating a data entry for xrefs.
            try:
                DataUtilities.createData(currentProgram, addr, qdt, -1, False, DataTypeConflictHandler.DEFAULT_HANDLER)
            except Exception as e:
                pass
            data_entry=listing.getDataAt(addr)
            refs=list(ref_mgr.getReferencesTo(addr))
            callers=[]
            for r in refs:
                fa=r.getFromAddress()
                func=func_mgr.getFunctionContaining(fa)
                callers.append({"from":scan_utils.format_address(fa.getOffset()),"type":r.getReferenceType().getName(),"function":func.getName() if func else None})
            results.append({"address":scan_utils.format_address(addr.getOffset()),"data_type":data_entry.getDataType().getName() if data_entry else None,"data_value":str(data_entry.getValue()) if data_entry else None,"callers":callers})
        with open(os.path.join(out_dir,'data_refs.json'),'w') as f:
            json.dump({"meta":{"build_id":build_id,"target_count":len(targets)},"results":results},f,indent=2,sort_keys=True)
        print("kernel_data_define_and_refs: processed %d targets"%len(targets))
    except Exception:
        if out_dir:
            try:
                _ensure(out_dir)
                with open(os.path.join(out_dir,'error.log'),'w') as err:
                    traceback.print_exc(file=err)
            except Exception:
                pass
        traceback.print_exc()

run()
