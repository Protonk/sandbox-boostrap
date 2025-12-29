'use strict';

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
