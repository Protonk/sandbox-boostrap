'use strict';

const TRACE_PATH = `/tmp/frida_sbtrace.${Process.id}.log`;
const MODULE_NAME = 'libsystem_sandbox.dylib';
const SYMBOL = 'sandbox_set_trace_path';
const VTRACE_ENABLE = 'sandbox_vtrace_enable';
const VTRACE_REPORT = 'sandbox_vtrace_report';
const VTRACE_BUF_SIZE = 16384;

const pError = Module.getGlobalExportByName('__error');
const fError = pError ? new NativeFunction(pError, 'pointer', []) : null;

function readErrno() {
  if (!fError) return null;
  return fError().readS32();
}

const findExport = (typeof Module.findExportByName === 'function')
  ? Module.findExportByName
  : Module.getExportByName;

function getExport(symbol) {
  try {
    return findExport(MODULE_NAME, symbol);
  } catch (_) {
    return null;
  }
}

const addrSetTrace = getExport(SYMBOL);
const addrVtraceEnable = getExport(VTRACE_ENABLE);
const addrVtraceReport = getExport(VTRACE_REPORT);

send({
  kind: 'sandbox-trace-capability',
  module: MODULE_NAME,
  has_sandbox_set_trace_path: !!addrSetTrace,
  has_sandbox_vtrace_enable: !!addrVtraceEnable,
  has_sandbox_vtrace_report: !!addrVtraceReport
});

if (addrSetTrace) {
  const fn = new NativeFunction(addrSetTrace, 'int', ['pointer']);
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
} else if (addrVtraceEnable && addrVtraceReport) {
  let enableRv = null;
  let reportRv = null;
  let report = null;
  let error = null;
  try {
    const enableFn = new NativeFunction(addrVtraceEnable, 'int', ['int']);
    const reportFn = new NativeFunction(addrVtraceReport, 'int', ['pointer', 'int']);
    enableRv = enableFn(1);
    const buf = Memory.alloc(VTRACE_BUF_SIZE);
    reportRv = reportFn(buf, VTRACE_BUF_SIZE);
    if (reportRv > 0) {
      report = buf.readUtf8String(Math.min(reportRv, VTRACE_BUF_SIZE - 1));
    }
  } catch (e) {
    error = String(e);
  }
  send({
    kind: 'sandbox-trace-vtrace',
    status: error ? 'error' : 'ok',
    module: MODULE_NAME,
    enable_rv: enableRv,
    report_rv: reportRv,
    report,
    errno: (reportRv === -1 || enableRv === -1) ? readErrno() : 0,
    error
  });
} else {
  send({
    kind: 'sandbox-trace-unavailable',
    module: MODULE_NAME,
    path: TRACE_PATH
  });
}
