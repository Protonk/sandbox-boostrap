"""Deterministic hook generator (v1).

This module is intentionally pure / headless:
- No Frida imports.
- No timestamps.
- No environment-derived values.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from book.api import path_utils
from book.api.frida import hook_manifest, trace_v1


class HookGeneratorError(Exception):
    pass


_HOOK_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]*$")


def _sha256_bytes(blob: bytes) -> str:
    h = hashlib.sha256()
    h.update(blob)
    return h.hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def format_manifest_json(manifest: Dict[str, Any]) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def _normalize_defaults(defaults_obj: Any) -> Dict[str, bool]:
    defaults: Dict[str, bool] = {
        "emit_backtrace": False,
        "emit_args": True,
        "emit_return": False,
    }
    if defaults_obj is None:
        return defaults
    if not isinstance(defaults_obj, dict):
        raise HookGeneratorError("HookGeneratorInputError: defaults must be an object")

    for key in list(defaults.keys()):
        if key not in defaults_obj:
            continue
        val = defaults_obj.get(key)
        if not isinstance(val, bool):
            raise HookGeneratorError(f"HookGeneratorInputError: defaults.{key} must be a boolean")
        defaults[key] = val
    return defaults


def _normalize_targets(targets_obj: Any) -> List[Dict[str, Any]]:
    if not isinstance(targets_obj, list) or not targets_obj:
        raise HookGeneratorError("HookGeneratorInputError: targets must be a non-empty array")

    targets: List[Dict[str, Any]] = []
    for i, t in enumerate(targets_obj):
        if not isinstance(t, dict):
            raise HookGeneratorError(f"HookGeneratorInputError: targets[{i}] must be an object")
        module = t.get("module")
        if not isinstance(module, str) or not module.strip():
            raise HookGeneratorError(f"HookGeneratorInputError: targets[{i}].module must be a non-empty string")

        exports = t.get("exports") or []
        if not isinstance(exports, list) or not all(isinstance(x, str) and x for x in exports):
            raise HookGeneratorError(f"HookGeneratorInputError: targets[{i}].exports must be an array of strings")

        export_patterns = t.get("export_patterns") or []
        if not isinstance(export_patterns, list) or not all(isinstance(x, str) and x for x in export_patterns):
            raise HookGeneratorError(
                f"HookGeneratorInputError: targets[{i}].export_patterns must be an array of strings"
            )

        exports_norm = sorted({x for x in exports if isinstance(x, str) and x})
        patterns_norm = sorted({x for x in export_patterns if isinstance(x, str) and x})
        if not exports_norm and not patterns_norm:
            raise HookGeneratorError(
                f"HookGeneratorInputError: targets[{i}] must include at least one of exports/export_patterns"
            )

        targets.append(
            {
                "module": module.strip(),
                "exports": exports_norm,
                "export_patterns": patterns_norm,
            }
        )

    targets.sort(key=lambda d: d["module"])
    return targets


def normalize_hook_generator_input_v1(input_obj: Any) -> Dict[str, Any]:
    if not isinstance(input_obj, dict):
        raise HookGeneratorError("HookGeneratorInputError: input must be a JSON object")

    hook_name = input_obj.get("hook_name")
    if not isinstance(hook_name, str) or not hook_name.strip():
        raise HookGeneratorError("HookGeneratorInputError: hook_name must be a non-empty string")
    hook_name = hook_name.strip()
    if not _HOOK_NAME_RE.match(hook_name):
        raise HookGeneratorError("HookGeneratorInputError: hook_name must match ^[A-Za-z0-9_][A-Za-z0-9_-]*$")

    description = input_obj.get("description")
    if not isinstance(description, str) or not description.strip():
        raise HookGeneratorError("HookGeneratorInputError: description must be a non-empty string")
    description = description.strip()

    targets = _normalize_targets(input_obj.get("targets"))
    defaults = _normalize_defaults(input_obj.get("defaults"))

    return {
        "hook_name": hook_name,
        "description": description,
        "targets": targets,
        "defaults": defaults,
    }


def _render_hook_js(*, norm: Dict[str, Any]) -> str:
    hook_name = str(norm["hook_name"])
    description = str(norm["description"])
    targets = norm["targets"]
    defaults = norm["defaults"]

    defaults_json = json.dumps(defaults, indent=2, sort_keys=True)
    targets_json = json.dumps(targets, indent=2)

    header = "\n".join(
        [
            "'use strict';",
            "",
            "// GENERATED FILE - DO NOT EDIT BY HAND.",
            f"// hook_name: {hook_name}",
            f"// description: {description}",
            "// input_schema: hook_generator_input_v1",
            f"// trace_event_schema: {trace_v1.TRACE_EVENT_SCHEMA_NAME} v{trace_v1.TRACE_EVENT_SCHEMA_VERSION}",
            f"// hook_manifest_schema: {hook_manifest.HOOK_MANIFEST_SCHEMA_NAME} v{hook_manifest.HOOK_MANIFEST_SCHEMA_VERSION}",
            "// configure_contract: v1",
            "",
        ]
    )

    body = f"""const HOOK_ID = {json.dumps(hook_name)};

const DEFAULT_CONFIG = {defaults_json};

let CONFIG = Object.assign({{}}, DEFAULT_CONFIG);
let _configured = false;
let _hooksInstalled = false;

const TARGETS = {targets_json};

function _captureBacktrace(ctx) {{
  return SL.backtrace(ctx, {{ include: !!CONFIG.emit_backtrace, limit: 20, mode: 'fuzzy' }});
}}

function _argsToStrings(args) {{
  if (!CONFIG.emit_args) return null;
  // TODO: decode args (types + strings)
  const out = [];
  for (let i = 0; i < 6; i++) {{
    try {{
      out.push(args[i].toString());
    }} catch (_) {{
      out.push(null);
    }}
  }}
  return out;
}}

function installHooks() {{
  if (_hooksInstalled) return;
  _hooksInstalled = true;

  for (const target of TARGETS) {{
    const moduleName = target.module;
    for (const exportName of (target.exports || [])) {{
      const addr = Module.findExportByName(moduleName, exportName);
      if (!addr) {{
        SL.emit('hook-missing', {{ module: moduleName, export: exportName }});
        continue;
      }}
      SL.emit('hook-installed', {{ module: moduleName, export: exportName, addr: addr.toString() }});

      Interceptor.attach(addr, {{
        onEnter(args) {{
          this.tid = Process.getCurrentThreadId();
          this.module = moduleName;
          this.export = exportName;
          this.args = _argsToStrings(args);
          this.bt = _captureBacktrace(this.context);
        }},
        onLeave(retval) {{
          const payload = {{
            module: this.module,
            export: this.export,
            tid: this.tid,
            args: this.args,
            bt: this.bt
          }};
          if (CONFIG.emit_return) {{
            // TODO: decode return value
            payload.ret = retval ? retval.toString() : null;
          }}
          SL.emit(HOOK_ID + '-call', payload);
        }}
      }});
    }}
  }}
}}

rpc.exports = {{
  configure: function (opts) {{
    if (_configured) {{
      throw new Error('configure called twice');
    }}
    _configured = true;
    if (!opts || typeof opts !== 'object') {{
      throw new Error('configure expects an object');
    }}

    CONFIG = Object.assign({{}}, DEFAULT_CONFIG, opts);
    installHooks();

    const keys = Object.keys(opts).sort();
    SL.emit(HOOK_ID + '-configured', {{ received_keys: keys }});
    return {{ received_keys: keys }};
  }}
}};
"""

    return header + body


def _build_manifest(*, norm: Dict[str, Any]) -> Dict[str, Any]:
    hook_name = str(norm["hook_name"])
    description = str(norm["description"])
    targets = norm["targets"]

    config_schema: Dict[str, Any] = {"type": "object", "additionalProperties": True}

    modules = sorted({t["module"] for t in targets if isinstance(t, dict) and isinstance(t.get("module"), str)})

    return {
        "schema_name": hook_manifest.HOOK_MANIFEST_SCHEMA_NAME,
        "schema_version": hook_manifest.HOOK_MANIFEST_SCHEMA_VERSION,
        "hook": {
            "id": hook_name,
            "script_path": f"book/api/frida/hooks/{hook_name}.js",
            "summary": description,
        },
        "trace_event_schema": trace_v1.trace_event_schema_stamp(),
        "config": {"schema": config_schema},
        "rpc": {"configure": {"present": True}},
        "rpc_exports": ["configure"],
        "configure": {"supported": True, "input_schema": config_schema},
        "module_expectations": [{"name": m, "required": True} for m in modules],
        "send_payload_kinds": [
            f"{hook_name}-call",
            f"{hook_name}-configured",
            "hook-installed",
            "hook-missing",
        ],
    }


def generate_hook_files(input_obj: Any) -> Dict[str, Any]:
    """
    Generate hook JS + manifest JSON from a v1 generator input object.

    Returns:
      {"hook_js": <str>, "manifest_json": <dict>}
    """
    norm = normalize_hook_generator_input_v1(input_obj)
    return {
        "hook_js": _render_hook_js(norm=norm),
        "manifest_json": _build_manifest(norm=norm),
    }


def write_generated_hook(
    output_dir: Path,
    hook_name: str,
    hook_js: str,
    manifest_json: Dict[str, Any],
    *,
    force: bool = False,
) -> Dict[str, Any]:
    """
    Deterministically write generated hook artifacts.

    Writes:
    - <output_dir>/<hook_name>.js
    - <output_dir>/<hook_name>.manifest.json
    """
    repo_root = path_utils.find_repo_root()
    out_dir = path_utils.ensure_absolute(output_dir, repo_root)
    out_dir.mkdir(parents=True, exist_ok=True)

    js_path = out_dir / f"{hook_name}.js"
    manifest_path = out_dir / f"{hook_name}.manifest.json"

    if not force and (js_path.exists() or manifest_path.exists()):
        raise HookGeneratorError(
            f"OutputExistsError: refusing to overwrite {hook_name}.js/{hook_name}.manifest.json (use --force)"
        )

    js_bytes = hook_js.encode("utf-8")
    manifest_text = format_manifest_json(manifest_json)
    manifest_bytes = manifest_text.encode("utf-8")

    js_path.write_bytes(js_bytes)
    manifest_path.write_bytes(manifest_bytes)

    return {
        "ok": True,
        "written": {
            "hook_js": path_utils.to_repo_relative(js_path, repo_root),
            "hook_js_sha256": _sha256_bytes(js_bytes),
            "manifest_json": path_utils.to_repo_relative(manifest_path, repo_root),
            "manifest_json_sha256": _sha256_bytes(manifest_bytes),
            "manifest_canonical_sha256": hook_manifest.sha256_canonical_json(manifest_json),
        },
        "generator_input_v": 1,
        "hook_name": hook_name,
    }

