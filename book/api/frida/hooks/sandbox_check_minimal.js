'use strict';

const MODULE = 'libsystem_sandbox.dylib';
const MAX_EVENTS = 40;
const INCLUDE_BT = true;

const TARGETS = new Set([
  'sandbox_check',
  'sandbox_check_bulk'
]);

function backtrace(ctx) {
  return SL.backtrace(ctx, { include: INCLUDE_BT, limit: 20, mode: 'fuzzy' });
}

function maybeCString(ptr) {
  try {
    if (ptr.isNull()) return null;
    return ptr.readUtf8String();
  } catch (_) {
    return null;
  }
}

let seen = 0;
let moduleObj;
try {
  moduleObj = Process.getModuleByName(MODULE);
} catch (e) {
  SL.emit('sandbox-minimal-error', { module: MODULE, error: String(e) });
  moduleObj = null;
}

if (moduleObj) {
  const exports = moduleObj.enumerateExports()
    .filter(e => e.type === 'function')
    .filter(e => TARGETS.has(e.name));

  SL.emit('sandbox-minimal-candidates', {
    module: MODULE,
    count: exports.length,
    names: exports.map(e => e.name)
  });

  for (const exp of exports) {
    const symbol = exp.name;
    const addr = exp.address;
    SL.emit('sandbox-minimal-hook', { module: MODULE, symbol, addr: addr.toString() });

    Interceptor.attach(addr, {
      onEnter(args) {
        if (seen >= MAX_EVENTS) return;
        this.symbol = symbol;
        this.tid = Process.getCurrentThreadId();
        this.args = [];
        for (let i = 0; i < 3; i++) {
          const ptrVal = args[i];
          this.args.push({
            ptr: ptrVal ? ptrVal.toString() : null,
            str: ptrVal ? maybeCString(ptrVal) : null
          });
        }
        this.bt = backtrace(this.context);
      },
      onLeave(retval) {
        if (seen >= MAX_EVENTS) return;
        seen += 1;
        SL.emit('sandbox-minimal-call', {
          symbol: this.symbol,
          tid: this.tid,
          args: this.args,
          ret: retval ? retval.toString() : null,
          ret_i32: retval ? retval.toInt32() : null,
          bt: this.bt
        });
      }
    });
  }
}
