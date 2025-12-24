'use strict';

const MODULES = [
  'libsystem_kernel.dylib',
  'libSystem.B.dylib',
  'libsystem_c.dylib'
];

const MAX_EVENTS = 50;
const ERROR_ERRNOS = {
  1: true,
  13: true
};

const INCLUDE_BT = true;
const MAX_BT_FRAMES = 20;

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

function normalizeSymbol(name) {
  let n = name;
  if (n.startsWith('__')) n = n.slice(2);
  if (n.includes('$')) n = n.split('$')[0];
  return n;
}

const META_NAMES = new Set([
  'getattrlist',
  'getattrlistat',
  'stat',
  'lstat',
  'fstatat',
  'access',
  'faccessat'
]);

const XATTR_NAMES = new Set([
  'getxattr',
  'fgetxattr',
  'listxattr',
  'flistxattr'
]);

function shouldHook(name) {
  if (name === 'syscall' || name === '__syscall') return true;
  const normalized = normalizeSymbol(name);
  if (META_NAMES.has(normalized) || XATTR_NAMES.has(normalized)) return true;
  if (normalized.startsWith('openat')) return true;
  if (normalized.startsWith('open')) return true;
  if (name.includes('openat_authenticated_np')) return true;
  if (name.includes('openat_dprotected_np')) return true;
  if (name.includes('open_dprotected_np')) return true;
  if (name.includes('guarded_open_dprotected_np')) return true;
  return false;
}

function classifySignature(symbol) {
  if (symbol === 'syscall' || symbol === '__syscall') return 'syscall';
  const normalized = normalizeSymbol(symbol);
  if (META_NAMES.has(normalized)) return normalized;
  if (XATTR_NAMES.has(normalized)) return normalized;
  if (normalized.includes('openat')) return 'openat';
  if (normalized.includes('open')) return 'open';
  return 'unknown';
}

function readPath(ptr) {
  try {
    if (ptr.isNull()) return null;
    return ptr.readUtf8String();
  } catch (_) {
    return null;
  }
}

const seenAddrs = new Set();
let seen = 0;

for (const moduleName of MODULES) {
  let moduleObj;
  try {
    moduleObj = Process.getModuleByName(moduleName);
  } catch (e) {
    send({ kind: 'funnel-error', module: moduleName, error: String(e) });
    continue;
  }

  const exports = moduleObj.enumerateExports()
    .filter(e => e.type === 'function')
    .filter(e => shouldHook(e.name));

  send({
    kind: 'funnel-candidates',
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

    const sig = classifySignature(symbol);
    send({ kind: 'funnel-hook', module: moduleName, symbol, addr: addrKey, sig });

    Interceptor.attach(addr, {
      onEnter(args) {
        this.tid = Process.getCurrentThreadId();
        this.symbol = symbol;
        this.sig = sig;
        this.module = moduleName;
        if (sig === 'syscall') {
          this.syscall_num = args[0].toInt32();
          this.arg1 = args[1];
          this.arg2 = args[2];
          this.arg3 = args[3];
          this.arg4 = args[4];
          this.arg5 = args[5];
          this.arg6 = args[6];
          this.path = readPath(this.arg1);
        } else if (sig === 'open') {
          this.path = readPath(args[0]);
          this.flags = args[1].toInt32();
          this.mode = args[2].toInt32();
        } else if (sig === 'openat') {
          this.dirfd = args[0].toInt32();
          this.path = readPath(args[1]);
          this.flags = args[2].toInt32();
          this.mode = args[3].toInt32();
        } else if (sig === 'stat' || sig === 'lstat') {
          this.path = readPath(args[0]);
        } else if (sig === 'fstatat') {
          this.dirfd = args[0].toInt32();
          this.path = readPath(args[1]);
          this.flags = args[3].toInt32();
        } else if (sig === 'access') {
          this.path = readPath(args[0]);
          this.mode = args[1].toInt32();
        } else if (sig === 'faccessat') {
          this.dirfd = args[0].toInt32();
          this.path = readPath(args[1]);
          this.mode = args[2].toInt32();
          this.flags = args[3].toInt32();
        } else if (sig === 'getattrlist') {
          this.path = readPath(args[0]);
        } else if (sig === 'getattrlistat') {
          this.dirfd = args[0].toInt32();
          this.path = readPath(args[1]);
        } else if (sig === 'getxattr') {
          this.path = readPath(args[0]);
          this.name = readPath(args[1]);
        } else if (sig === 'fgetxattr') {
          this.fd = args[0].toInt32();
          this.name = readPath(args[1]);
        } else if (sig === 'listxattr') {
          this.path = readPath(args[0]);
        } else if (sig === 'flistxattr') {
          this.fd = args[0].toInt32();
        }
      },
      onLeave(retval) {
        const rv = retval.toInt32();
        if (rv !== -1) return;
        const errno = readErrno();
        if (!ERROR_ERRNOS[errno]) return;
        if (seen >= MAX_EVENTS) return;
        seen += 1;
        send({
          kind: 'funnel-hit',
          module: this.module,
          symbol: this.symbol,
          sig: this.sig,
          tid: this.tid,
          syscall_num: this.syscall_num,
          dirfd: this.dirfd,
          fd: this.fd,
          path: this.path,
          name: this.name,
          flags: this.flags,
          mode: this.mode,
          rv,
          errno,
          bt: backtrace(this.context)
        });
      }
    });
  }
}
