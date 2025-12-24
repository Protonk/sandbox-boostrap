'use strict';

const LOG_SUCCESSES = false;
const INCLUDE_BT = true;
const MAX_BT_FRAMES = 20;
const SELF_OPEN_DELAY_MS = 50;

const pError = Module.getGlobalExportByName('__error');
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

function hookOpenLike(symbol, arity) {
  const addr = Module.getGlobalExportByName(symbol);
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
        this.path = args[0].isNull() ? null : args[0].readUtf8String();
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

function envValue(key) {
  try {
    const env = Process.enumerateEnvironment();
    for (const kv of env) {
      if (kv.key === key) return kv.value;
    }
  } catch (_) {
    return null;
  }
  return null;
}

function resolveHome() {
  const envHome = envValue('HOME') || envValue('PWD');
  if (envHome) return envHome;
  if (typeof ObjC !== 'undefined' && ObjC.available && ObjC.classes.NSFileManager) {
    try {
      const fm = ObjC.classes.NSFileManager.defaultManager();
      const url = fm.homeDirectoryForCurrentUser();
      if (url) {
        const path = url.path();
        if (path) return path.toString();
      }
    } catch (_) {
      return null;
    }
  }
  if (typeof ObjC !== 'undefined' && ObjC.available) {
    try {
      const nsHomeAddr = Module.getGlobalExportByName('NSHomeDirectory');
      if (nsHomeAddr) {
        const nsHomeFn = new NativeFunction(nsHomeAddr, 'pointer', []);
        const nsHome = nsHomeFn();
        if (!nsHome.isNull()) {
          return new ObjC.Object(nsHome).toString();
        }
      }
    } catch (_) {
      return null;
    }
  }
  try {
    const getcwdAddr = Module.getGlobalExportByName('getcwd');
    if (getcwdAddr) {
      const getcwdFn = new NativeFunction(getcwdAddr, 'pointer', ['pointer', 'ulong']);
      const buf = Memory.alloc(4096);
      const res = getcwdFn(buf, 4096);
      if (!res.isNull()) {
        return buf.readUtf8String();
      }
    }
  } catch (_) {
    return null;
  }
  return null;
}

function selfOpen() {
  const home = resolveHome();
  const targetPath = home ? `${home}/tmp/ej_noaccess` : '/tmp/ej_noaccess';
  const openAddr = Module.getGlobalExportByName('open');
  if (!openAddr) {
    send({ kind: 'self-open', status: 'open-missing', path: targetPath });
    return;
  }
  const closeAddr = Module.getGlobalExportByName('close');
  const openFn = new NativeFunction(openAddr, 'int', ['pointer', 'int', 'int']);
  const closeFn = closeAddr ? new NativeFunction(closeAddr, 'int', ['int']) : null;
  send({ kind: 'self-open', status: 'attempt', path: targetPath });
  const cPath = Memory.allocUtf8String(targetPath);
  const fd = openFn(cPath, 0, 0);
  if (fd >= 0 && closeFn) {
    closeFn(fd);
  }
}

hookOpenLike('open', 3);
hookOpenLike('openat', 4);
hookOpenLike('fopen', 2);

setTimeout(selfOpen, SELF_OPEN_DELAY_MS);
