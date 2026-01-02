'use strict';

const TARGET_PATH = (() => {
  if (typeof Process.enumerateEnvironment === 'function') {
    try {
      const env = Process.enumerateEnvironment();
      for (const kv of env) {
        if (kv.key === 'FRIDA_SELFTEST_PATH') return kv.value;
      }
    } catch (_) {
      return '/tmp/frida_testing_noaccess';
    }
  }
  return '/tmp/frida_testing_noaccess';
})();

const pError = Module.getGlobalExportByName('__error');
const fError = pError ? new NativeFunction(pError, 'pointer', []) : null;

function readErrno() {
  if (!fError) return null;
  return fError().readS32();
}

let didFire = false;

const symbol = 'open';
const addr = Module.getGlobalExportByName(symbol);
if (!addr) {
  send({ kind: 'interceptor-selftest', status: 'symbol-missing', symbol });
} else {
  send({ kind: 'interceptor-selftest', status: 'hook-installed', symbol, addr: addr.toString() });

  Interceptor.attach(addr, {
    onEnter(args) {
      didFire = true;
      this.path = args[0].isNull() ? null : args[0].readUtf8String();
      this.flags = args[1].toInt32();
      this.mode = args[2].toInt32();
    },
    onLeave(retval) {
      send({
        kind: 'interceptor-selftest',
        status: 'hook-fired',
        symbol,
        path: this.path,
        flags: this.flags,
        mode: this.mode,
        rv: retval.toInt32(),
        errno: readErrno()
      });
    }
  });

  const openFn = new NativeFunction(addr, 'int', ['pointer', 'int', 'int']);
  const closeAddr = Module.getGlobalExportByName('close');
  const closeFn = closeAddr ? new NativeFunction(closeAddr, 'int', ['int']) : null;
  const cPath = Memory.allocUtf8String(TARGET_PATH);
  const fd = openFn(cPath, 0, 0);
  if (fd >= 0 && closeFn) closeFn(fd);

  send({
    kind: 'interceptor-selftest',
    status: 'call-complete',
    symbol,
    did_fire: didFire,
    target_path: TARGET_PATH,
    rv: fd,
    errno: fd < 0 ? readErrno() : 0
  });
}
