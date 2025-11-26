## 1. What this example is about

This example is a **profile compiler** for the system SBPL profiles:

* It walks over `.sb` files (by default `airlock.sb` and `bsd.sb` in `/System/Library/Sandbox/Profiles`).
* It calls the private `sandbox_compile_file` entry point in `libsandbox.dylib`.
* It pulls out the compiled policy blob (the “profile graph”).
* It writes `*.sb.bin` files you can disassemble or diff.

Conceptually, this is a **modern replacement for kernelcache scraping**:

* Old workflows pulled profile blobs out of the kernelcache by offset.
* This tool asks `libsandbox` directly to compile SBPL → TinyScheme → graph, exactly as in runtime.
* The resulting blobs match the binary layout described in Appendix.md (header + op tables + node array + literal/regex tables).

The example shows how to automate that pipeline in userland with Python + `ctypes`.

---

## 2. How to run and what to expect

Files:

* `compile_profiles.py` – Python CLI that loads `libsandbox` and compiles profiles.
* `run-demo.sh` – zsh wrapper that calls the Python tool with sensible defaults.

Typical usage:

```sh
# From the example directory
./run-demo.sh
```

This will:

* Create `build/profiles` under the example root.
* Compile:

  * `/System/Library/Sandbox/Profiles/airlock.sb`
  * `/System/Library/Sandbox/Profiles/bsd.sb`
* Write:

  * `build/profiles/airlock.sb.bin`
  * `build/profiles/bsd.sb.bin`
* Print for each profile:

  * byte count
  * a short hex preview of the compiled blob.

Direct Python usage:

```sh
python3 compile_profiles.py \
  --profiles-dir /System/Library/Sandbox/Profiles \
  --names airlock.sb bsd.sb \
  --out-dir build/profiles
```

You can extend this with extra profile names or `--param` settings as described below.

---

## 3. The `SandboxProfile` struct and libsandbox binding

At the top of `compile_profiles.py`:

```python
class SandboxProfile(ctypes.Structure):
    _fields_ = [
        ("profile_type", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("bytecode", ctypes.c_void_p),
        ("bytecode_length", ctypes.c_size_t),
    ]
```

This mirrors the small struct returned by `sandbox_compile_file`:

* `profile_type` – indicates the compilation mode (plain SBPL, app sandbox, etc.).
* `reserved` – padding/unused in this context.
* `bytecode` – pointer to the compiled binary profile blob.
* `bytecode_length` – size of that blob.

The layout matches the conceptual “header struct + pointer” used in the C examples: it is not the full on-disk format, it’s the **API wrapper** around it.

The library loader:

```python
def _load_libsandbox():
    try:
        return ctypes.CDLL("libsandbox.dylib")
    except OSError as exc:
        raise SystemExit(f"failed to load libsandbox.dylib: {exc}") from exc
```

This:

* Uses `ctypes.CDLL("libsandbox.dylib")` to load the userland `libsandbox` dynamic library.
* Exits with a clear error if the library is not present or cannot be loaded.

---

## 4. Parameter block for the compiler

```python
def _build_param_array(param_pairs):
    """
    Build a NULL-terminated array of char* for sandbox_compile_file/string.

    Expected format (older sandbox_init_with_parameters style):
      ["KEY1", "VALUE1", "KEY2", "VALUE2", ..., NULL]
    """
    if not param_pairs:
        return None

    flat = []
    for key, value in param_pairs:
        flat.extend([key.encode(), value.encode()])
    arr_type = ctypes.c_char_p * (len(flat) + 1)
    return arr_type(*flat, None)
```

This models the classic `sandbox_init_with_parameters` parameter vector:

* Input: list of `(KEY, VALUE)` tuples.
* Output: a `char *argv[]`-style array:

  * `["KEY1", "VALUE1", "KEY2", "VALUE2", ..., NULL]`

Conceptually, this lets you pass **compile-time parameters** to SBPL, such as:

* Profile mode switches,
* App identifiers,
* Environment-style knobs.

In this example, parameters are optional and default to none, but the code path is there so you can experiment with `--param KEY=VALUE` later.

---

## 5. Compiling a profile: `compile_profile`

The core function:

```python
def compile_profile(lib, path: Path, param_pairs) -> bytes:
    """Compile an SBPL file and return the compiled bytecode blob."""
    err = ctypes.c_char_p()
    params = _build_param_array(param_pairs)

    lib.sandbox_compile_file.argtypes = [
        ctypes.c_char_p,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    lib.sandbox_compile_file.restype = ctypes.POINTER(SandboxProfile)
    lib.sandbox_free_profile.argtypes = [ctypes.POINTER(SandboxProfile)]
    lib.sandbox_free_profile.restype = None

    profile = lib.sandbox_compile_file(str(path).encode(), 0, params)
    if not profile:
        detail = err.value.decode() if err.value else "unknown error"
        raise SystemExit(f"compile failed for {path}: {detail}")

    bc_len = profile.contents.bytecode_length
    bc_ptr = profile.contents.bytecode
    blob = ctypes.string_at(bc_ptr, bc_len)
    lib.sandbox_free_profile(profile)
    if err:
        libc = ctypes.CDLL(None)
        libc.free(err)
    return blob
```

Step-by-step:

1. Build the parameter array for this profile:

   * `params = _build_param_array(param_pairs)`
2. Describe the C signatures to `ctypes`:

   * `sandbox_compile_file`:

     * `const char *path`
     * `uint64_t flags` (here 0)
     * parameter pointer (older parameter style)
     * returns `SandboxProfile *`
   * `sandbox_free_profile`:

     * takes `SandboxProfile *`
     * returns nothing.
3. Call `sandbox_compile_file(str(path).encode(), 0, params)`:

   * `path` is the `.sb` file.
   * `flags` is 0 for now.
   * `params` carries any optional KEY=VALUE pairs.
4. If no profile is returned:

   * The compilation failed; a `SystemExit` is raised with a message.
5. On success:

   * Read `bytecode_length` and `bytecode` from the `SandboxProfile`.
   * Use `ctypes.string_at` to copy that many bytes into a Python `bytes` object.
   * Call `sandbox_free_profile(profile)` to let `libsandbox` free the struct and its internal allocations.
6. Return the `blob` as a `bytes` object.

Conceptually, this is the **SBPL → compiled graph** step:

* The input `.sb` file goes through TinyScheme and the internal compiler inside `libsandbox`.
* The output `blob` is exactly what the kernel’s Seatbelt evaluator uses at runtime.

---

## 6. Hex preview

```python
def hex_preview(blob: bytes, count: int = 32) -> str:
    """Render a short preview of the compiled profile bytes."""
    preview = blob[:count]
    grouped = ["".join(f"{b:02x}" for b in preview[i : i + 8]) for i in range(0, len(preview), 8)]
    return " " .join(grouped)
```

This turns the first `count` bytes (default 32) into a compact hex string:

* Groups into chunks of 8 bytes.
* Concatenates each group’s bytes into a 16-character hex string.
* Joins groups with spaces.

It does not interpret the structure; it simply provides a stable **fingerprint** that you can glance at or diff across OS versions or compiler parameter changes.

---

## 7. CLI: choosing profiles and outputs

`main()` wires everything into a small CLI:

```python
def main():
    default_profiles = ["airlock.sb", "bsd.sb"]
    parser = argparse.ArgumentParser(
        description="Compile SBPL profiles to binary blobs using libsandbox (macOS 14.x)."
    )
    parser.add_argument(
        "--profiles-dir",
        type=Path,
        default=Path("/System/Library/Sandbox/Profiles"),
        help="Directory containing .sb files (default: system profiles).",
    )
    parser.add_argument(
        "--names",
        nargs="+",
        default=default_profiles,
        help="Profile filenames to compile (default: %(default)s).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("build/profiles"),
        help="Where to write .sb.bin outputs (created if missing).",
    )
    parser.add_argument(
        "--param",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Optional parameter to pass to the compiler (repeatable).",
    )
    args = parser.parse_args()
```

Arguments:

* `--profiles-dir`:

  * Where to look for `.sb` files.
  * Defaults to the system profiles directory.
* `--names`:

  * One or more profile filenames (no path, just the `.sb` names).
  * Defaults to `airlock.sb` and `bsd.sb`.
* `--out-dir`:

  * Target directory for `*.sb.bin` outputs.
  * Defaults to `build/profiles`.
* `--param`:

  * Repeatable `KEY=VALUE` options.
  * Passed through to the compiler via `_build_param_array`.

Parameter parsing:

```python
    param_pairs = []
    for item in args.param:
        if "=" not in item:
            parser.error(f"--param must be KEY=VALUE, got {item!r}")
        key, value = item.split("=", 1)
        param_pairs.append((key, value))
```

This enforces the `KEY=VALUE` format and builds a list of `(key, value)` tuples for `_build_param_array`.

The main compilation loop:

```python
    lib = _load_libsandbox()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    for name in args.names:
        sb_path = args.profiles_dir / name
        if not sb_path.exists():
            print(f"[skip] {sb_path} (not found)")
            continue

        print(f"[+] compiling {sb_path}")
        try:
            blob = compile_profile(lib, sb_path, param_pairs)
        except SystemExit as exc:
            print(f"    error: {exc}")
            continue

        out_path = args.out_dir / f"{name}.bin"
        out_path.write_bytes(blob)
        print(f"    wrote {out_path} ({len(blob)} bytes)")
        print(f"    preview: {hex_preview(blob)}")
```

Behavior:

* Loads `libsandbox` once.
* Ensures `out_dir` exists.
* For each profile name:

  * Compute `sb_path`.
  * Skip if the file is missing.
  * Compile via `compile_profile`.
  * On success:

    * Write `out_dir/name.sb.bin`.
    * Print size and hex preview.
  * On failure:

    * Print the error and continue to the next profile.

This produces a **small corpus of compiled profiles** you can feed into downstream tools.

---

## 8. Wrapper script: `run-demo.sh`

```bash
#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/build/profiles"
PROFILES_DIR="/System/Library/Sandbox/Profiles"
NAMES=("airlock.sb" "bsd.sb")

mkdir -p "$OUT"

echo "[*] compiling profiles from $PROFILES_DIR"
python3 "$ROOT/compile_profiles.py" --profiles-dir "$PROFILES_DIR" --names "${NAMES[@]}" --out-dir "$OUT"

echo
echo "[*] outputs in $OUT (feed these .sb.bin files into sbdis or other decoders)."
```

Key points:

* Uses strict shell flags:

  * `-e` – exit on error,
  * `-u` – error on undefined variables,
  * `pipefail` – catch pipeline errors.
* Computes absolute `ROOT` from the script location.
* Sets:

  * `OUT` = `${ROOT}/build/profiles`.
  * `PROFILES_DIR` = system profiles directory.
  * `NAMES` = array of profile filenames.
* Creates the output directory.
* Invokes the Python tool with explicit `--profiles-dir`, `--names`, and `--out-dir`.
* Reminds you at the end to use `sbdis` or similar to inspect the resulting blobs.

This gives you a **one-command demo**: `./run-demo.sh`.

---

## 9. How to use this as a learning scaffold

This example is meant to be run side-by-side with the Orientation and Appendix documents:

1. **From SBPL text to binary graph**

   * Open `/System/Library/Sandbox/Profiles/airlock.sb` in a text editor.
   * Run `./run-demo.sh`.
   * Then inspect `build/profiles/airlock.sb.bin` with your own disassembler or graph visualizer.
   * The blob you see corresponds exactly to the “header + operation pointers + node array + literal/regex tables” layout described in Appendix.md.

2. **Diff across OS versions / configs**

   * On different macOS versions or machines, run the same script.
   * Compare:

     * Blob sizes,
     * Hex previews,
     * Full decoded graphs if you have a disassembler.
   * This reveals **evolution of platform profiles** over time.

3. **Experiment with parameters**

   * Add `--param` flags when running `compile_profiles.py` directly.
   * This lets you explore how parameterized SBPL constructs respond to compile-time inputs.

4. **Extend the profile set**

   * Change `NAMES` in `run-demo.sh` or pass `--names` on the CLI to target:

     * more system profiles,
     * or your own test profiles in a different directory.

In short, `extract_sbs` is a **userland harness** around `libsandbox`’s SBPL compiler. It turns opaque on-disk `.sb` text profiles into binary blobs you can analyze, diff, and map back to the conceptual policy graph described elsewhere in the documentation.
