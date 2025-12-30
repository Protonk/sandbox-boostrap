'use strict';
const DEFAULT_CONFIG = {
    emit_on_configure: true
};
let CONFIG = Object.assign({}, DEFAULT_CONFIG);
let configured = false;
function emitSmoke() {
    let codeSigningPolicy = null;
    try {
        codeSigningPolicy = Process.codeSigningPolicy ?? null;
    }
    catch (_) {
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
    configure: function (opts) {
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
