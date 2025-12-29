'use strict';

const LOG_SUCCESSES = false;
const INCLUDE_BT = true;
const MAX_BT_FRAMES = 20;
const SELF_OPEN_DELAY_MS = 150;

const SELFTEST_CONFIG = {
  path: null,
  source: null
};

rpc.exports = {
  configure: function (opts) {
    if (opts && opts.selftest_path) {
      SELFTEST_CONFIG.path = String(opts.selftest_path);
      SELFTEST_CONFIG.source = 'rpc';
    }
    return SELFTEST_CONFIG;
  }
};

const pError = Module.getGlobalExportByName('__error');
const fError = pError ? new NativeFunction(pError, 'pointer', []) : null;

function readErrno() {
  if (!fError) return null;
  return fError().readS32();
}

function backtrace(ctx) {
  return SL.backtrace(ctx, { include: INCLUDE_BT, limit: MAX_BT_FRAMES, mode: 'fuzzy' });
}

function hookOpenLike(symbol, arity) {
  const addr = Module.getGlobalExportByName(symbol);
  if (!addr) {
    SL.emit('hook-missing', { symbol });
    return;
  }
  SL.emit('hook-installed', { symbol, addr: addr.toString() });

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
        SL.emit('fs-open', {
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
        SL.emit('fs-open', {
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

function resolveSelftestPath() {
  if (SELFTEST_CONFIG.path) {
    return { path: SELFTEST_CONFIG.path, source: SELFTEST_CONFIG.source || 'rpc' };
  }
  const envPath = envValue('FRIDA_SELFTEST_PATH');
  if (envPath) {
    return { path: envPath, source: 'env' };
  }
  const home = resolveHome();
  if (home) {
    return { path: `${home}/tmp/ej_noaccess`, source: 'home' };
  }
  return { path: '/tmp/ej_noaccess', source: 'default' };
}

function selfOpen() {
  const resolved = resolveSelftestPath();
  const targetPath = resolved.path;
  const openAddr = Module.getGlobalExportByName('open');
  if (!openAddr) {
    SL.emit('self-open', { status: 'open-missing', path: targetPath, source: resolved.source });
    return;
  }
  const closeAddr = Module.getGlobalExportByName('close');
  const openFn = new NativeFunction(openAddr, 'int', ['pointer', 'int', 'int']);
  const closeFn = closeAddr ? new NativeFunction(closeAddr, 'int', ['int']) : null;
  SL.emit('self-open', { status: 'attempt', path: targetPath, source: resolved.source });
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
