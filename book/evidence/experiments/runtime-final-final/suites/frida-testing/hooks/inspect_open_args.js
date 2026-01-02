'use strict';

function safeString(v) {
  try { return String(v); } catch (e) { return 'error:' + String(e); }
}

function protoKeys(v) {
  try { return Object.getOwnPropertyNames(Object.getPrototypeOf(v)).sort(); } catch (e) { return ['error:' + String(e)]; }
}

let done = false;
let openPtr = null;
try {
  openPtr = Module.getGlobalExportByName('open');
  send({ kind: 'open-export', symbol: 'open', addr: safeString(openPtr) });
} catch (e) {
  send({ kind: 'open-export-missing', symbol: 'open', error: String(e) });
}

if (openPtr) {
  Interceptor.attach(openPtr, {
    onEnter(args) {
      if (done) return;
      done = true;
      const a0 = args[0];
      send({
        kind: 'inspect-open-args',
        a0_typeof: typeof a0,
        a0_str: safeString(a0),
        a0_isNull_typeof: typeof a0.isNull,
        a0_toInt32_typeof: typeof a0.toInt32,
        a0_proto_keys: protoKeys(a0),
      });
    },
  });
}
