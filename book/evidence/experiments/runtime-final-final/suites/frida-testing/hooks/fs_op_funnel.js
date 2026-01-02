'use strict';

const MODULES = [
  'libsystem_kernel.dylib',
  'libSystem.B.dylib',
  'libsystem_c.dylib'
];

const MAX_EVENTS = 200;
const INCLUDE_BT_ON_ERROR = true;
let pathSubstr = null;

rpc.exports = {
  configure(cfg) {
    if (cfg && typeof cfg.path_substr === 'string') {
      pathSubstr = cfg.path_substr;
    }
  }
};

const OPS = new Set([
  'creat',
  'mkdir',
  'mkdirat',
  'rename',
  'renameat',
  'renamex_np',
  'renameatx_np',
  'unlink',
  'unlinkat',
  'rmdir'
]);

const pError = Module.getGlobalExportByName('__error');
const fError = pError ? new NativeFunction(pError, 'pointer', []) : null;

function readErrno() {
  if (!fError) return null;
  return fError().readS32();
}

function backtrace(ctx) {
  if (!INCLUDE_BT_ON_ERROR) return null;
  try {
    return Thread.backtrace(ctx, Backtracer.FUZZY)
      .slice(0, 20)
      .map(DebugSymbol.fromAddress)
      .map(s => s.toString());
  } catch (_) {
    return null;
  }
}

function normalizeSymbol(name) {
  let n = name;
  if (n.startsWith('__')) n = n.slice(2);
  if (n.includes('$')) n = n.split('$')[0];
  return n;
}

function readPath(ptr) {
  try {
    if (ptr.isNull()) return null;
    return ptr.readUtf8String();
  } catch (_) {
    return null;
  }
}

function shouldEmit(path, path2) {
  if (!pathSubstr) return true;
  if (path && path.includes(pathSubstr)) return true;
  if (path2 && path2.includes(pathSubstr)) return true;
  return false;
}

function decodeArgs(sig, args) {
  if (sig === 'creat') {
    return { path: readPath(args[0]), mode: args[1].toInt32() };
  }
  if (sig === 'mkdir') {
    return { path: readPath(args[0]), mode: args[1].toInt32() };
  }
  if (sig === 'mkdirat') {
    return { dirfd: args[0].toInt32(), path: readPath(args[1]), mode: args[2].toInt32() };
  }
  if (sig === 'rename') {
    return { path: readPath(args[0]), path2: readPath(args[1]) };
  }
  if (sig === 'renamex_np') {
    return { path: readPath(args[0]), path2: readPath(args[1]), flags: args[2].toInt32() };
  }
  if (sig === 'renameat') {
    return {
      dirfd: args[0].toInt32(),
      path: readPath(args[1]),
      dirfd2: args[2].toInt32(),
      path2: readPath(args[3])
    };
  }
  if (sig === 'renameatx_np') {
    return {
      dirfd: args[0].toInt32(),
      path: readPath(args[1]),
      dirfd2: args[2].toInt32(),
      path2: readPath(args[3]),
      flags: args[4].toInt32()
    };
  }
  if (sig === 'unlink') {
    return { path: readPath(args[0]) };
  }
  if (sig === 'unlinkat') {
    return { dirfd: args[0].toInt32(), path: readPath(args[1]), flags: args[2].toInt32() };
  }
  if (sig === 'rmdir') {
    return { path: readPath(args[0]) };
  }
  return {};
}

const seenAddrs = new Set();
let seen = 0;

for (const moduleName of MODULES) {
  let moduleObj;
  try {
    moduleObj = Process.getModuleByName(moduleName);
  } catch (e) {
    send({ kind: 'fs-op-funnel-error', module: moduleName, error: String(e) });
    continue;
  }

  const exports = moduleObj.enumerateExports()
    .filter(e => e.type === 'function')
    .filter(e => OPS.has(normalizeSymbol(e.name)));

  send({
    kind: 'fs-op-funnel-candidates',
    module: moduleName,
    count: exports.length,
    names: exports.map(e => e.name)
  });

  for (const exp of exports) {
    const symbol = exp.name;
    const addr = exp.address;
    const addrKey = addr.toString();
    if (seenAddrs.has(addrKey)) {
      continue;
    }
    seenAddrs.add(addrKey);

    const sig = normalizeSymbol(symbol);
    send({ kind: 'fs-op-funnel-hook', module: moduleName, symbol, addr: addrKey, sig });

    Interceptor.attach(addr, {
      onEnter(args) {
        this.tid = Process.getCurrentThreadId();
        this.symbol = symbol;
        this.sig = sig;
        this.module = moduleName;
        const decoded = decodeArgs(sig, args);
        Object.assign(this, decoded);
      },
      onLeave(retval) {
        if (seen >= MAX_EVENTS) return;
        const rv = retval.toInt32();
        const errno = rv === -1 ? readErrno() : 0;
        if (!shouldEmit(this.path, this.path2)) return;
        seen += 1;
        send({
          kind: 'fs-op-funnel',
          module: this.module,
          symbol: this.symbol,
          sig: this.sig,
          tid: this.tid,
          dirfd: this.dirfd,
          dirfd2: this.dirfd2,
          path: this.path,
          path2: this.path2,
          flags: this.flags,
          mode: this.mode,
          rv,
          errno,
          bt: rv === -1 ? backtrace(this.context) : null
        });
      }
    });
  }
}
