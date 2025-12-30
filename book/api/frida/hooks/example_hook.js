'use strict';

// GENERATED FILE - DO NOT EDIT BY HAND.
// hook_name: example_hook
// description: Example generated hook for golden-output tests.
// input_schema: hook_generator_input_v1
// trace_event_schema: book.api.frida.trace_event v1
// hook_manifest_schema: book.api.frida.hook_manifest v1
// configure_contract: v1
const HOOK_ID = "example_hook";

const DEFAULT_CONFIG = {
  "emit_args": true,
  "emit_backtrace": false,
  "emit_return": false
};

let CONFIG = Object.assign({}, DEFAULT_CONFIG);
let _configured = false;
let _hooksInstalled = false;

const TARGETS = [
  {
    "module": "libsystem_kernel.dylib",
    "exports": [
      "open",
      "open$NOCANCEL"
    ],
    "export_patterns": []
  },
  {
    "module": "libsystem_sandbox.dylib",
    "exports": [
      "sandbox_check",
      "sandbox_check_by_audit_token"
    ],
    "export_patterns": [
      "^sandbox_check_.*$"
    ]
  }
];

function _captureBacktrace(ctx) {
  return SL.backtrace(ctx, { include: !!CONFIG.emit_backtrace, limit: 20, mode: 'fuzzy' });
}

function _argsToStrings(args) {
  if (!CONFIG.emit_args) return null;
  // TODO: decode args (types + strings)
  const out = [];
  for (let i = 0; i < 6; i++) {
    try {
      out.push(args[i].toString());
    } catch (_) {
      out.push(null);
    }
  }
  return out;
}

function installHooks() {
  if (_hooksInstalled) return;
  _hooksInstalled = true;

  for (const target of TARGETS) {
    const moduleName = target.module;
    for (const exportName of (target.exports || [])) {
      const addr = Module.findExportByName(moduleName, exportName);
      if (!addr) {
        SL.emit('hook-missing', { module: moduleName, export: exportName });
        continue;
      }
      SL.emit('hook-installed', { module: moduleName, export: exportName, addr: addr.toString() });

      Interceptor.attach(addr, {
        onEnter(args) {
          this.tid = Process.getCurrentThreadId();
          this.module = moduleName;
          this.export = exportName;
          this.args = _argsToStrings(args);
          this.bt = _captureBacktrace(this.context);
        },
        onLeave(retval) {
          const payload = {
            module: this.module,
            export: this.export,
            tid: this.tid,
            args: this.args,
            bt: this.bt
          };
          if (CONFIG.emit_return) {
            // TODO: decode return value
            payload.ret = retval ? retval.toString() : null;
          }
          SL.emit(HOOK_ID + '-call', payload);
        }
      });
    }
  }
}

rpc.exports = {
  configure: function (opts) {
    if (_configured) {
      throw new Error('configure called twice');
    }
    _configured = true;
    if (!opts || typeof opts !== 'object') {
      throw new Error('configure expects an object');
    }

    CONFIG = Object.assign({}, DEFAULT_CONFIG, opts);
    installHooks();

    const keys = Object.keys(opts).sort();
    SL.emit(HOOK_ID + '-configured', { received_keys: keys });
    return { received_keys: keys };
  }
};
