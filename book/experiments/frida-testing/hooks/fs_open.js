'use strict';

const LOG_SUCCESSES = false;      // keep noise down
const INCLUDE_BT = true;          // flip off if too heavy
const MAX_BT_FRAMES = 20;

function findGlobal(symbol) {
  try {
    return Module.getGlobalExportByName(symbol);
  } catch (_) {
    return null;
  }
}

const pError = findGlobal('__error');
const fError = pError ? new NativeFunction(pError, 'pointer', []) : null;

function readErrno() {
  if (!fError) return null;
  return fError().readS32();
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

function hookOpen() {
  hookOpenSymbol('open');
}

function hookOpenat() {
  hookOpenatSymbol('openat');
}

function hookFopen() {
  const symbol = 'fopen';
  const addr = findGlobal(symbol);
  if (!addr) return send({ kind: 'hook-missing', symbol });
  send({ kind: 'hook-installed', symbol, addr: addr.toString() });

  Interceptor.attach(addr, {
    onEnter(args) {
      this.tid = Process.getCurrentThreadId();
      this.path = args[0].isNull() ? null : args[0].readUtf8String();
      this.mode_str = args[1].isNull() ? null : args[1].readUtf8String();
      this.bt = backtrace(this.context);
    },
    onLeave(retval) {
      const ok = !retval.isNull();
      if (ok && !LOG_SUCCESSES) return;
      send({
        kind: 'fs-open',
        symbol,
        tid: this.tid,
        path: this.path,
        mode_str: this.mode_str,
        rv: ok ? 0 : -1,
        errno: ok ? 0 : readErrno(),
        bt: this.bt
      });
    }
  });
}

function hookOpenSymbol(symbol) {
  const addr = findGlobal(symbol);
  if (!addr) return send({ kind: 'hook-missing', symbol });
  send({ kind: 'hook-installed', symbol, addr: addr.toString() });

  Interceptor.attach(addr, {
    onEnter(args) {
      this.tid = Process.getCurrentThreadId();
      this.path = args[0].isNull() ? null : args[0].readUtf8String();
      this.flags = args[1].toInt32();
      this.mode = args[2].toInt32();
      this.bt = backtrace(this.context);
    },
    onLeave(retval) {
      const rv = retval.toInt32();
      if (rv !== -1 && !LOG_SUCCESSES) return;
      send({
        kind: 'fs-open',
        symbol,
        tid: this.tid,
        path: this.path,
        flags: this.flags,
        mode: this.mode,
        rv,
        errno: rv === -1 ? readErrno() : 0,
        bt: this.bt
      });
    }
  });
}

function hookOpenatSymbol(symbol) {
  const addr = findGlobal(symbol);
  if (!addr) return send({ kind: 'hook-missing', symbol });
  send({ kind: 'hook-installed', symbol, addr: addr.toString() });

  Interceptor.attach(addr, {
    onEnter(args) {
      this.tid = Process.getCurrentThreadId();
      this.dirfd = args[0].toInt32();
      this.path = args[1].isNull() ? null : args[1].readUtf8String();
      this.flags = args[2].toInt32();
      this.mode = args[3].toInt32();
      this.bt = backtrace(this.context);
    },
    onLeave(retval) {
      const rv = retval.toInt32();
      if (rv !== -1 && !LOG_SUCCESSES) return;
      send({
        kind: 'fs-open',
        symbol,
        tid: this.tid,
        dirfd: this.dirfd,
        path: this.path,
        flags: this.flags,
        mode: this.mode,
        rv,
        errno: rv === -1 ? readErrno() : 0,
        bt: this.bt
      });
    }
  });
}

// cover the common Darwin variants; whichever exist will hook
hookOpen();
hookOpenat();
hookFopen();
hookOpenSymbol('open$NOCANCEL');
hookOpenatSymbol('openat$NOCANCEL');
hookOpenSymbol('__open');
hookOpenSymbol('__open_nocancel');
hookOpenatSymbol('__openat');
hookOpenatSymbol('__openat_nocancel');
