'use strict';

const TRACE_PATH = `/tmp/frida_sbtrace.${Process.id}.log`;
const MODULE_NAME = 'libsystem_sandbox.dylib';
const SYMBOL = 'sandbox_set_trace_path';

const pError = Module.getGlobalExportByName('__error');
const fError = pError ? new NativeFunction(pError, 'pointer', []) : null;

function readErrno() {
  if (!fError) return null;
  return fError().readS32();
}

const findExport = (typeof Module.findExportByName === 'function')
  ? Module.findExportByName
  : Module.getExportByName;

let addr = null;
try {
  addr = findExport(MODULE_NAME, SYMBOL);
} catch (_) {
  addr = null;
}
if (!addr) {
  send({
    kind: 'sandbox-trace',
    status: 'symbol-missing',
    module: MODULE_NAME,
    symbol: SYMBOL,
    path: TRACE_PATH
  });
} else {
  const fn = new NativeFunction(addr, 'int', ['pointer']);
  const cPath = Memory.allocUtf8String(TRACE_PATH);
  const rv = fn(cPath);
  send({
    kind: 'sandbox-trace',
    status: 'set-trace',
    module: MODULE_NAME,
    symbol: SYMBOL,
    path: TRACE_PATH,
    rv,
    errno: rv === -1 ? readErrno() : 0
  });
}
