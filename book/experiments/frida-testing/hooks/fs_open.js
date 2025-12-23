'use strict';

const LOG_SUCCESSES = false;      // keep noise down
const INCLUDE_BT = true;          // flip off if too heavy
const MAX_BT_FRAMES = 20;

const pError = Module.findExportByName(null, '__error');
const fError = pError ? new NativeFunction(pError, 'pointer', []) : null;

function readErrno() {
  if (!fError) return null;
  return Memory.readS32(fError());
}

function backtrace(ctx) {
  if (!INCLUDE_BT) return null;
  try {
    return Thread.backtrace(ctx, Backtracer.FUZZY)
      .slice(0, MAX_BT_FRAMES)
      .map(DebugSymbol.fromAddress)
      .map(s => s.toString());
  } catch (_) {
    return null;
  }
}

function hookOpenLike(symbol, arity) {
  const addr = Module.findExportByName(null, symbol);
  if (!addr) {
    send({ kind: 'hook-missing', symbol });
    return;
  }
  send({ kind: 'hook-installed', symbol, addr: addr.toString() });

  Interceptor.attach(addr, {
    onEnter(args) {
      this.tid = Process.getCurrentThreadId();
      this.symbol = symbol;

      if (arity >= 1) {
        this.path = args[0].isNull() ? null : Memory.readUtf8String(args[0]);
      }
      if (arity >= 2) {
        this.flags = args[1].toInt32();
      }
      if (arity >= 3) {
        this.mode = args[2].toInt32();
      }

      this.bt = backtrace(this.context);
    },
    onLeave(retval) {
      const rv = retval.toInt32();
      if (rv === -1) {
        const e = readErrno();
        send({
          kind: 'fs-open',
          symbol: this.symbol,
          tid: this.tid,
          path: this.path,
          flags: this.flags,
          mode: this.mode,
          rv,
          errno: e,
          bt: this.bt
        });
        return;
      }

      if (LOG_SUCCESSES) {
        send({
          kind: 'fs-open',
          symbol: this.symbol,
          tid: this.tid,
          path: this.path,
          flags: this.flags,
          mode: this.mode,
          rv,
          errno: 0,
          bt: this.bt
        });
      }
    }
  });
}

// cover the common Darwin variants; whichever exist will hook
hookOpenLike('open', 3);
hookOpenLike('openat', 4);
hookOpenLike('fopen', 2);
// optional: hookOpenLike('open$NOCANCEL', 3); hookOpenLike('openat$NOCANCEL', 4);
