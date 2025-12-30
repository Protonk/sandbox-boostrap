'use strict';

// TypeScript-authored hook compiled into book/api/frida/hooks/smoke_ts.js.
// This script assumes the shared helper is injected by the loader (see book/api/frida/script_assembly.py).

declare const SL: {
  send: (payload: Record<string, unknown>) => void;
};

declare const rpc: {
  exports: Record<string, unknown>;
};

declare const Process: {
  id: number;
  arch: string;
  platform: string;
  codeSigningPolicy?: string;
};

type SmokeConfig = {
  emit_on_configure?: boolean;
};

const DEFAULT_CONFIG: SmokeConfig = {
  emit_on_configure: true
};

let CONFIG: SmokeConfig = Object.assign({}, DEFAULT_CONFIG);
let configured = false;

function emitSmoke(): void {
  let codeSigningPolicy: string | null = null;
  try {
    codeSigningPolicy = (Process as any).codeSigningPolicy ?? null;
  } catch (_) {
    codeSigningPolicy = null;
  }

  SL.send({
    kind: "smoke_ts",
    pid: Process.id,
    arch: Process.arch,
    platform: Process.platform,
    code_signing_policy: codeSigningPolicy
  });
}

rpc.exports = {
  configure: function (opts: Record<string, unknown>) {
    if (configured) {
      throw new Error("configure called twice");
    }
    configured = true;
    if (!opts || typeof opts !== "object") {
      throw new Error("configure expects an object");
    }

    CONFIG = Object.assign({}, DEFAULT_CONFIG, opts);
    if (CONFIG.emit_on_configure) {
      emitSmoke();
    }

    const keys = Object.keys(opts).sort();
    return { received_keys: keys };
  }
};

