'use strict';

function dumpExports(moduleName) {
  const m = Process.getModuleByName(moduleName);
  const exps = m.enumerateExports()
    .filter(e => e.name.startsWith('sandbox_'))
    .map(e => ({ name: e.name, type: e.type, address: e.address.toString() }));
  send({ kind: 'exports', module: moduleName, count: exps.length, exports: exps });
}

try {
  dumpExports('libsystem_sandbox.dylib');
} catch (e) {
  send({ kind: 'exports-error', module: 'libsystem_sandbox.dylib', error: String(e) });
}
