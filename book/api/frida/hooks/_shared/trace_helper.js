'use strict';

// Shared helper for SANDBOX_LORE Frida hooks.
//
// This module intentionally standardizes only payload-level conventions:
// - emission helpers
// - backtrace capture helpers
//
// The Python-side runner/capture owns the trace v1 envelope.

const SL = (() => {
  function sendRaw(payload) {
    send(payload);
  }

  function emit(kind, fields) {
    const obj = Object.assign({ kind }, fields || {});
    send(obj);
  }

  function backtrace(ctx, opts) {
    const include = opts && opts.include;
    const limit = (opts && typeof opts.limit === 'number') ? opts.limit : 20;
    const mode = (opts && opts.mode === 'accurate') ? Backtracer.ACCURATE : Backtracer.FUZZY;

    if (!include) return null;
    try {
      return Thread.backtrace(ctx, mode)
        .slice(0, limit)
        .map(DebugSymbol.fromAddress)
        .map(s => s.toString());
    } catch (_) {
      return null;
    }
  }

  return {
    send: sendRaw,
    emit,
    backtrace
  };
})();

