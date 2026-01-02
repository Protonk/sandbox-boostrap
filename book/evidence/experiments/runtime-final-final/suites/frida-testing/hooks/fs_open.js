'use strict';

const LOG_SUCCESSES = false;      // keep noise down
const INCLUDE_BT = true;          // only on errno 1/13
const MAX_BT_FRAMES = 20;
const ERROR_BT_ERRNOS = { 1: true, 13: true };

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

function maybeBt(errno, ctx) {
  if (!ERROR_BT_ERRNOS[errno]) return null;
  return backtrace(ctx);
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
    },
    onLeave(retval) {
      const rv = retval.toInt32();
      if (rv !== -1 && !LOG_SUCCESSES) return;
      const errno = rv === -1 ? readErrno() : 0;
      send({
        kind: 'fs-open',
        symbol,
        tid: this.tid,
        path: this.path,
        flags: this.flags,
        mode: this.mode,
        rv,
        errno,
        bt: rv === -1 ? maybeBt(errno, this.context) : null
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
    },
    onLeave(retval) {
      const rv = retval.toInt32();
      if (rv !== -1 && !LOG_SUCCESSES) return;
      const errno = rv === -1 ? readErrno() : 0;
      send({
        kind: 'fs-open',
        symbol,
        tid: this.tid,
        dirfd: this.dirfd,
        path: this.path,
        flags: this.flags,
        mode: this.mode,
        rv,
        errno,
        bt: rv === -1 ? maybeBt(errno, this.context) : null
      });
    }
  });
}

// minimal hook pack; keep openat for coverage, plus $INODE64 variants when present
hookOpenSymbol('__open');
hookOpenSymbol('open');
hookOpenSymbol('__open$INODE64');
hookOpenSymbol('open$INODE64');
hookOpenatSymbol('openat');
hookOpenatSymbol('__openat');
hookOpenatSymbol('openat$INODE64');
hookOpenatSymbol('__openat$INODE64');
