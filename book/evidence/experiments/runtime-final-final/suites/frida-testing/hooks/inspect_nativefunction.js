'use strict';

function safe(fn) {
  try { return fn(); } catch (e) { return 'error:' + String(e); }
}

function ownKeys(v) {
  try { return Object.getOwnPropertyNames(v).sort(); } catch (_) { return null; }
}

function protoKeys(v) {
  try { return Object.getOwnPropertyNames(Object.getPrototypeOf(v)).sort(); } catch (_) { return null; }
}

const pError = safe(() => Module.getGlobalExportByName('__error'));
let fNew = null;
let fNoNew = null;
let fNewType = null;
let fNoNewType = null;
let fNewCall = null;
let fNoNewCall = null;

if (typeof pError === 'object') {
  fNewCall = safe(() => {
    fNew = new NativeFunction(pError, 'pointer', []);
    fNewType = typeof fNew;
    return typeof fNew === 'function' ? String(fNew()) : '<not-callable>';
  });
  fNoNewCall = safe(() => {
    fNoNew = NativeFunction(pError, 'pointer', []);
    fNoNewType = typeof fNoNew;
    return typeof fNoNew === 'function' ? String(fNoNew()) : '<not-callable>';
  });
}

send({
  kind: 'inspect-nativefunction',
  pError_typeof: typeof pError,
  pError_str: String(pError),
  new_typeof: fNewType,
  new_own_keys: ownKeys(fNew),
  new_proto_keys: protoKeys(fNew),
  new_call: fNewCall,
  nonew_typeof: fNoNewType,
  nonew_own_keys: ownKeys(fNoNew),
  nonew_proto_keys: protoKeys(fNoNew),
  nonew_call: fNoNewCall,
});
