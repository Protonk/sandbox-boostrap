'use strict';

let _configured = false;

function emitSmoke() {
  let codeSigningPolicy = null;
  try {
    codeSigningPolicy = Process.codeSigningPolicy;
  } catch (_) {
    codeSigningPolicy = null;
  }

  SL.send({
    kind: "smoke",
    pid: Process.id,
    arch: Process.arch,
    platform: Process.platform,
    code_signing_policy: codeSigningPolicy
  });
}

rpc.exports = {
  configure: function (opts) {
    if (_configured) {
      throw new Error("configure called twice");
    }
    _configured = true;
    const keys = (opts && typeof opts === 'object') ? Object.keys(opts).sort() : [];
    emitSmoke();
    return { received_keys: keys };
  }
};
