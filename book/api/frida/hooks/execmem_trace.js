'use strict';

const MODULES = [
  'libsystem_kernel.dylib',
  'libSystem.B.dylib',
  'libsystem_pthread.dylib',
  'libdyld.dylib'
];

const MAX_EVENTS = 80;
const INCLUDE_BT = true;

const PROT_READ = 0x1;
const PROT_WRITE = 0x2;
const PROT_EXEC = 0x4;
const MAP_JIT = 0x800;

const pError = Module.getGlobalExportByName('__error');
const fError = pError ? new NativeFunction(pError, 'pointer', []) : null;

function readErrno() {
  if (!fError) return null;
  return fError().readS32();
}

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

function normalizeSymbol(name) {
  let n = name;
  if (n.startsWith('__')) n = n.slice(2);
  if (n.includes('$')) n = n.split('$')[0];
  return n;
}

const TARGETS = new Set([
  'mmap',
  'mprotect',
  'dlopen',
  'dlclose',
  'dlopen_preflight',
  'pthread_jit_write_protect_np'
]);

let seen = 0;
const seenAddrs = new Set();

for (const moduleName of MODULES) {
  let moduleObj;
  try {
    moduleObj = Process.getModuleByName(moduleName);
  } catch (e) {
    SL.emit('execmem-error', { module: moduleName, error: String(e) });
    continue;
  }

  const exports = moduleObj.enumerateExports()
    .filter(e => e.type === 'function')
    .filter(e => TARGETS.has(normalizeSymbol(e.name)));

  SL.emit('execmem-candidates', {
    module: moduleName,
    count: exports.length,
    names: exports.map(e => e.name)
  });

  for (const exp of exports) {
    const symbol = exp.name;
    const addr = exp.address;
    const addrKey = addr.toString();
    if (seenAddrs.has(addrKey)) continue;
    seenAddrs.add(addrKey);

    const sig = normalizeSymbol(symbol);
    SL.emit('execmem-hook', { module: moduleName, symbol, addr: addrKey, sig });

    Interceptor.attach(addr, {
      onEnter(args) {
        if (seen >= MAX_EVENTS) return;
        this.sig = sig;
        this.symbol = symbol;
        this.tid = Process.getCurrentThreadId();
        if (sig === 'mmap') {
          this.len = args[1].toInt32();
          this.prot = args[2].toInt32();
          this.flags = args[3].toInt32();
          this.fd = args[4].toInt32();
        } else if (sig === 'mprotect') {
          this.len = args[1].toInt32();
          this.prot = args[2].toInt32();
        } else if (sig === 'dlopen') {
          this.path = maybeCString(args[0]);
          this.mode = args[1].toInt32();
        } else if (sig === 'dlopen_preflight') {
          this.path = maybeCString(args[0]);
        } else if (sig === 'pthread_jit_write_protect_np') {
          this.enabled = args[0].toInt32();
        }
      },
      onLeave(retval) {
        if (seen >= MAX_EVENTS) return;
        seen += 1;
        const prot = this.prot ?? null;
        const flags = this.flags ?? null;
        const hasExec = prot !== null && (prot & PROT_EXEC) !== 0;
        const hasJit = flags !== null && (flags & MAP_JIT) !== 0;
        const retInt = retval ? retval.toInt32() : null;
        const errno = (this.sig === 'mprotect' && retInt === -1) ? readErrno() : null;
        const includeBt = hasExec || hasJit || (errno !== null);
        SL.emit('execmem-call', {
          sig: this.sig,
          symbol: this.symbol,
          tid: this.tid,
          len: this.len,
          prot: prot,
          flags: flags,
          fd: this.fd,
          path: this.path,
          mode: this.mode,
          enabled: this.enabled,
          ret: retval ? retval.toString() : null,
          ret_i32: retInt,
          errno: errno,
          prot_exec: hasExec,
          map_jit: hasJit,
          bt: includeBt ? backtrace(this.context) : null
        });
      }
    });
  }
}
