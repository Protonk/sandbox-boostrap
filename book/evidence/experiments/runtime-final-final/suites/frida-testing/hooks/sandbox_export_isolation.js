'use strict';

const MODULE = 'libsystem_sandbox.dylib';
const DEFAULT_MAX_EVENTS = 40;
const DEFAULT_MAX_BT_FRAMES = 20;
const DEFAULT_ARG_COUNT = 4;
const DEFAULT_INCLUDE_BT = true;

let moduleObj = null;
try {
  moduleObj = Process.getModuleByName(MODULE);
} catch (e) {
  send({ kind: 'sandbox-export-error', module: MODULE, error: String(e) });
  moduleObj = null;
}

function backtrace(ctx, maxFrames) {
  try {
    return Thread.backtrace(ctx, Backtracer.FUZZY)
      .slice(0, maxFrames)
      .map(DebugSymbol.fromAddress)
      .map(s => s.toString());
  } catch (_) {
    return null;
  }
}

function maybeCString(ptr) {
  try {
    if (!ptr || ptr.isNull()) return null;
    return ptr.readUtf8String();
  } catch (_) {
    return null;
  }
}

function readArg(ptr) {
  if (!ptr) return { ptr: null, str: null };
  return { ptr: ptr.toString(), str: maybeCString(ptr) };
}

function normalizeOptions(opts) {
  const cfg = {
    list_only: false,
    symbols: [],
    symbol: null,
    symbol_prefix: null,
    symbol_regex: null,
    max_events: DEFAULT_MAX_EVENTS,
    include_bt: DEFAULT_INCLUDE_BT,
    max_bt_frames: DEFAULT_MAX_BT_FRAMES,
    arg_count: DEFAULT_ARG_COUNT
  };
  if (!opts) return cfg;
  if (opts.list_only) cfg.list_only = true;
  if (Array.isArray(opts.symbols)) cfg.symbols = opts.symbols.map(String);
  if (opts.symbol) cfg.symbol = String(opts.symbol);
  if (opts.symbol_prefix) cfg.symbol_prefix = String(opts.symbol_prefix);
  if (opts.symbol_regex) cfg.symbol_regex = String(opts.symbol_regex);
  if (typeof opts.max_events === 'number') cfg.max_events = opts.max_events;
  if (typeof opts.include_bt === 'boolean') cfg.include_bt = opts.include_bt;
  if (typeof opts.max_bt_frames === 'number') cfg.max_bt_frames = opts.max_bt_frames;
  if (typeof opts.arg_count === 'number') cfg.arg_count = opts.arg_count;
  return cfg;
}

function listExports() {
  if (!moduleObj) return [];
  return moduleObj.enumerateExports()
    .filter(e => e.type === 'function')
    .map(e => ({ name: e.name, address: e.address }));
}

function selectSymbols(cfg, exports) {
  const names = exports.map(e => e.name);
  const nameSet = new Set(names);
  const selected = new Set();
  const missing = [];
  let regexError = null;

  for (const sym of cfg.symbols) {
    if (nameSet.has(sym)) selected.add(sym);
    else missing.push(sym);
  }
  if (cfg.symbol && nameSet.has(cfg.symbol)) selected.add(cfg.symbol);
  if (cfg.symbol && !nameSet.has(cfg.symbol)) missing.push(cfg.symbol);
  if (cfg.symbol_prefix) {
    for (const name of names) {
      if (name.startsWith(cfg.symbol_prefix)) selected.add(name);
    }
  }
  if (cfg.symbol_regex) {
    try {
      const re = new RegExp(cfg.symbol_regex);
      for (const name of names) {
        if (re.test(name)) selected.add(name);
      }
    } catch (e) {
      regexError = String(e);
    }
  }
  return { selected: Array.from(selected), missing, regexError };
}

rpc.exports = {
  configure: function (opts) {
    const cfg = normalizeOptions(opts);
    if (!moduleObj) {
      return { status: 'error', error: 'module-missing' };
    }

    const exports = listExports();
    send({
      kind: 'sandbox-export-list',
      module: MODULE,
      count: exports.length,
      names: exports.map(e => e.name)
    });

    if (cfg.list_only) {
      return { status: 'listed', count: exports.length };
    }

    const selection = selectSymbols(cfg, exports);
    send({
      kind: 'sandbox-export-selection',
      requested: cfg,
      count: selection.selected.length,
      names: selection.selected,
      missing: selection.missing,
      regex_error: selection.regexError
    });

    if (selection.selected.length === 0) {
      return { status: 'no-symbols', count: 0 };
    }

    const addrMap = new Map(exports.map(e => [e.name, e.address]));
    let seen = 0;

    for (const symbol of selection.selected) {
      const addr = addrMap.get(symbol);
      if (!addr) continue;
      send({ kind: 'sandbox-export-hook', module: MODULE, symbol, addr: addr.toString() });

      Interceptor.attach(addr, {
        onEnter(args) {
          if (seen >= cfg.max_events) return;
          this.symbol = symbol;
          this.tid = Process.getCurrentThreadId();
          this.args = [];
          for (let i = 0; i < cfg.arg_count; i++) {
            this.args.push(readArg(args[i]));
          }
          this.bt = cfg.include_bt ? backtrace(this.context, cfg.max_bt_frames) : null;
        },
        onLeave(retval) {
          if (seen >= cfg.max_events) return;
          seen += 1;
          send({
            kind: 'sandbox-export-call',
            symbol: this.symbol,
            tid: this.tid,
            args: this.args,
            ret: retval ? retval.toString() : null,
            ret_i32: retval ? retval.toInt32() : null,
            bt: this.bt
          });
        }
      });
    }

    return { status: 'hooked', count: selection.selected.length };
  }
};
