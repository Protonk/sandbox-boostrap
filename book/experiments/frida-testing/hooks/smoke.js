'use strict';

let codeSigningPolicy = null;
try {
  codeSigningPolicy = Process.codeSigningPolicy;
} catch (_) {
  codeSigningPolicy = null;
}

send({
  kind: "smoke",
  pid: Process.id,
  arch: Process.arch,
  platform: Process.platform,
  code_signing_policy: codeSigningPolicy
});
