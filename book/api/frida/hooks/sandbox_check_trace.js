'use strict';

const MODULE = 'libsystem_sandbox.dylib';
const MAX_EVENTS = 80;
const INCLUDE_BT = true;

function backtrace(ctx) {
  if (!INCLUDE_BT) return null;
  try {
    return Thread.backtrace(ctx, Backtracer.FUZZY)
      .slice(0, 20)
      .map(DebugSymbol.fromAddress)
      .map(s => s.toString());
  } catch (_) {
    return null;
  }
}

function maybeCString(ptr) {
  try {
    if (ptr.isNull()) return null;
    return ptr.readUtf8String();
  } catch (_) {
    return null;
  }
}

function shouldHook(name) {
  return name.startsWith('sandbox_check') ||
    name.startsWith('sandbox_extension_issue') ||
    name.startsWith('sandbox_extension_consume') ||
    name.startsWith('sandbox_consume_extension') ||
    name.startsWith('sandbox_extension_release') ||
    name.startsWith('sandbox_extension_update') ||
    name.startsWith('sandbox_issue_');
}

let seen = 0;
let moduleObj;
try {
  moduleObj = Process.getModuleByName(MODULE);
} catch (e) {
  send({ kind: 'sandbox-hook-error', module: MODULE, error: String(e) });
  moduleObj = null;
}

if (moduleObj) {
  const exports = moduleObj.enumerateExports()
    .filter(e => e.type === 'function')
    .filter(e => shouldHook(e.name));

  send({
    kind: 'sandbox-hook-candidates',
    module: MODULE,
    count: exports.length,
    names: exports.map(e => e.name)
  });

  for (const exp of exports) {
    const symbol = exp.name;
    const addr = exp.address;
    send({ kind: 'sandbox-hook', module: MODULE, symbol, addr: addr.toString() });

    Interceptor.attach(addr, {
      onEnter(args) {
        if (seen >= MAX_EVENTS) return;
        this.symbol = symbol;
        this.tid = Process.getCurrentThreadId();
        this.args = [];
        for (let i = 0; i < 4; i++) {
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
        send({
          kind: 'sandbox-call',
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
