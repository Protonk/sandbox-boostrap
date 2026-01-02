'use strict';

function safeTypeof(v) {
  try { return typeof v; } catch (_) { return '<typeof-error>'; }
}

function ownKeys(v) {
  try { return Object.getOwnPropertyNames(v).sort(); } catch (_) { return null; }
}

function protoKeys(v) {
  try { return Object.getOwnPropertyNames(Object.getPrototypeOf(v)).sort(); } catch (_) { return null; }
}

const p0 = ptr('0x0');
const isNullT = safeTypeof(p0.isNull);
let isNullV = null;
if (isNullT === 'function') {
  try { isNullV = p0.isNull(); } catch (e) { isNullV = 'call-error:' + String(e); }
} else {
  try { isNullV = p0.isNull; } catch (e) { isNullV = 'get-error:' + String(e); }
}

send({
  kind: 'inspect-primitives',
  ptr_typeof: safeTypeof(p0),
  ptr_own_keys: ownKeys(p0),
  ptr_proto_keys: protoKeys(p0),
  ptr_isNull_typeof: isNullT,
  ptr_isNull_value: isNullV,
  nativefunction_typeof: safeTypeof(NativeFunction),
  nativefunction_own_keys: ownKeys(NativeFunction),
});
