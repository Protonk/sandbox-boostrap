'use strict';

const DEFAULT_EXTENSION = 'com.apple.app-sandbox.read';
const DEFAULT_PATH = '/etc/hosts';
const DEFAULT_DELAY_MS = 150;

const SELFTEST = {
  extension: DEFAULT_EXTENSION,
  path: DEFAULT_PATH,
  flags: 0,
  delay_ms: DEFAULT_DELAY_MS
};

rpc.exports = {
  configure: function (opts) {
    if (opts) {
      if (opts.extension) SELFTEST.extension = String(opts.extension);
      if (opts.path) SELFTEST.path = String(opts.path);
      if (opts.flags !== undefined) SELFTEST.flags = Number(opts.flags);
      if (opts.delay_ms !== undefined) SELFTEST.delay_ms = Number(opts.delay_ms);
      if (opts.selftest_path && !opts.path) SELFTEST.path = String(opts.selftest_path);
    }
    return SELFTEST;
  }
};

const pError = Module.getGlobalExportByName('__error');
const fError = pError ? new NativeFunction(pError, 'pointer', []) : null;

function readErrno() {
  if (!fError) return null;
  return fError().readS32();
}

function report(kind, payload) {
  send(Object.assign({ kind }, payload || {}));
}

function callExtensions() {
  const issueAddr = Module.getGlobalExportByName('sandbox_extension_issue_file');
  const consumeAddr = Module.getGlobalExportByName('sandbox_extension_consume');
  const releaseAddr = Module.getGlobalExportByName('sandbox_extension_release');

  if (!issueAddr || !consumeAddr || !releaseAddr) {
    report('sandbox-extension-error', {
      issue: issueAddr ? issueAddr.toString() : null,
      consume: consumeAddr ? consumeAddr.toString() : null,
      release: releaseAddr ? releaseAddr.toString() : null
    });
    return;
  }

  const issueFn = new NativeFunction(issueAddr, 'pointer', ['pointer', 'pointer', 'uint64']);
  const consumeFn = new NativeFunction(consumeAddr, 'int', ['pointer']);
  const releaseFn = new NativeFunction(releaseAddr, 'int', ['pointer']);

  const extPtr = Memory.allocUtf8String(SELFTEST.extension);
  const pathPtr = Memory.allocUtf8String(SELFTEST.path);

  report('sandbox-extension-issue-attempt', {
    extension: SELFTEST.extension,
    path: SELFTEST.path,
    flags: SELFTEST.flags
  });
  const tokenPtr = issueFn(extPtr, pathPtr, SELFTEST.flags);
  if (tokenPtr.isNull()) {
    report('sandbox-extension-issue-failed', { errno: readErrno() });
    return;
  }

  let token = null;
  try {
    token = tokenPtr.readUtf8String();
  } catch (_) {
    token = null;
  }

  report('sandbox-extension-issued', { token });

  const consumeRv = consumeFn(tokenPtr);
  report('sandbox-extension-consume', {
    rv: consumeRv,
    errno: consumeRv === 0 ? 0 : readErrno()
  });

  const releaseRv = releaseFn(tokenPtr);
  report('sandbox-extension-release', {
    rv: releaseRv,
    errno: releaseRv === 0 ? 0 : readErrno()
  });
}

setTimeout(callExtensions, SELFTEST.delay_ms);
