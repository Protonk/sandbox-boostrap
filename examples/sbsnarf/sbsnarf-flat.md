## 1. What this example is about

This example is a minimal **SBPL → binary sandbox profile compiler**:

* Input: an SBPL source file (`*.sb`).
* Output: a compiled sandbox blob (`*.sb.bin`) in the same format `libsandbox` would normally hand to the kernel.
* Implementation: thin Python wrapper around the private `sandbox_compile_file` API in `libsandbox.dylib`.

It is intentionally small and generic:

* No repo-specific ingestion logic.
* No decoding or analysis.
* Just “take SBPL, call `libsandbox`, write the raw bytecode out.”

You use `sbsnarf.py` as the front-end when you want to generate compiled blobs for further inspection by other tools (`sbdis`, `re2dot`, `resnarf`, custom analyzers).

---

## 2. How to run it

Command-line usage:

```sh
./sbsnarf.py input.sb output.sb.bin
```

Where:

* `input.sb` is any SBPL file you can feed to `libsandbox`.
* `output.sb.bin` is the binary sandbox blob to be written (directories will be created if needed).

Example:

```sh
# Make it executable
chmod +x sbsnarf.py

# Compile a sample profile
./sbsnarf.py sample.sb build/sample.sb.bin
```

If compilation succeeds you will see something like:

```text
[+] compiled sample.sb -> build/sample.sb.bin (len=1234, type=1)
```

You can then:

* Run `sbdis` on `build/sample.sb.bin` (if it’s a legacy format).
* Run any graph/ingestion tooling that understands the modern compiled format.
* Archive or diff the blob across SBPL changes or OS versions.

If the compile fails, the script exits with a message from `libsandbox` (if available), e.g.:

```text
compile failed: syntax error near ...
```

---

## 3. The `SandboxProfile` struct

At the top of the script:

```python
class SandboxProfile(ctypes.Structure):
    _fields_ = [
        ("profile_type", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("bytecode", ctypes.c_void_p),
        ("bytecode_length", ctypes.c_size_t),
    ]
```

This mirrors the struct `sandbox_compile_file` returns:

* `profile_type`:

  * 32-bit type/format indicator from `libsandbox`.
  * Used here only for logging (`type=...`); downstream tools can use it to distinguish legacy vs modern formats.
* `reserved`:

  * Currently unused; included to match the ABI.
* `bytecode`:

  * Pointer to the compiled sandbox profile bytes.
* `bytecode_length`:

  * Number of bytes at `bytecode`.

`ctypes` uses this struct layout to read back the fields from the pointer that `sandbox_compile_file` returns.

---

## 4. Core compiler function: `compile_sbpl`

```python
def compile_sbpl(src: Path, dst: Path):
    lib = ctypes.CDLL("libsandbox.dylib")
```

Step-by-step:

### 4.1 Load `libsandbox` and declare function signatures

```python
    lib.sandbox_compile_file.argtypes = [
        ctypes.c_char_p,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    lib.sandbox_compile_file.restype = ctypes.POINTER(SandboxProfile)
    lib.sandbox_free_profile.argtypes = [ctypes.POINTER(SandboxProfile)]
    lib.sandbox_free_profile.restype = None
```

This tells `ctypes`:

* `sandbox_compile_file` has signature roughly:

  ```c
  struct sandbox_profile *sandbox_compile_file(
      const char *path,
      uint64_t flags,
      char **errorbuf
  );
  ```

* `sandbox_free_profile` has signature:

  ```c
  void sandbox_free_profile(struct sandbox_profile *profile);
  ```

So:

* `argtypes` specify:

  * `const char *` (file path),
  * `uint64_t` (flags, here `0`),
  * `char **` (pointer to error buffer).
* `restype` says the result is a pointer to `SandboxProfile`.

### 4.2 Call the compiler and handle errors

```python
    err = ctypes.c_char_p()
    profile = lib.sandbox_compile_file(str(src).encode(), 0, ctypes.byref(err))
    if not profile:
        detail = err.value.decode() if err.value else "unknown error"
        raise SystemExit(f"compile failed: {detail}")
```

* `err` is a `char *` initialized to `NULL`.
* `sandbox_compile_file` is called with:

  * `src` path as a UTF-8 `char *`.
  * Flags = `0`.
  * Address of `err` so the function can fill it with an error string on failure.
* If `profile` is `NULL`:

  * The script extracts `detail` from `err` if present.
  * Exits with `compile failed: <detail>`.

This is the only compile-time error handling: no parsing is done locally; the SBPL is passed as-is to `libsandbox`.

### 4.3 Copy and write the compiled blob

```python
    blob = ctypes.string_at(profile.contents.bytecode, profile.contents.bytecode_length)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(blob)
    print(f"[+] compiled {src} -> {dst} (len={profile.contents.bytecode_length}, type={profile.contents.profile_type})")
```

* `ctypes.string_at(ptr, length)` copies `bytecode_length` bytes from `bytecode` into a Python `bytes` object.
* Ensures the destination directory exists.
* Writes the blob verbatim to `dst`.
* Logs:

  * Length in bytes.
  * Profile type (for quick format sanity checks).

This written `*.sb.bin` file is exactly what you'd feed into decoders or to the kernel (indirectly through OS mechanisms).

### 4.4 Cleanup

```python
    lib.sandbox_free_profile(profile)
    if err:
        ctypes.CDLL(None).free(err)
```

* Calls `sandbox_free_profile(profile)` to release the memory allocated for the compiled profile.
* If `err` is non-null, it calls `free(err)` from the default C library (`ctypes.CDLL(None)`), because `libsandbox` allocated that error buffer.

This avoids memory leaks inside the host process when compiling many profiles in a loop.

---

## 5. CLI wrapper: `main()`

```python
def main():
    if len(sys.argv) != 3:
        print("usage: sbsnarf.py input.sb output.sb.bin")
        sys.exit(1)

    compile_sbpl(Path(sys.argv[1]), Path(sys.argv[2]))
```

* Expects exactly two arguments: input SBPL path and output blob path.
* If the argument count is wrong, prints a short usage string and exits.
* Otherwise converts both to `Path` and calls `compile_sbpl`.

Standard `if __name__ == "__main__": main()` at the end makes it directly executable.

---

## 6. How this fits in the broader sandbox tooling

Compared with other examples:

* `compile_sample.py` (in `sb/`):

  * Compiles a specific sample SBPL.
  * Immediately passes the blob through the shared ingestion layer and prints header/section info.
* `extract_sbs`, `sbdis`, `re2dot`, `resnarf`:

  * Operate on **compiled blobs** and reverse-engineer structure (decision trees, NFAs, headers, etc.).

`sbsnarf.py` is the **generic compiler** at the front of that chain:

* Take any `*.sb` you want to experiment with.
* Use `sbsnarf.py` to turn it into `*.sb.bin`.
* Feed the result into:

  * Legacy disassemblers (`sbdis`) if it’s an early format.
  * Modern ingestion-based decoders to inspect headers, ops, and regex tables.
  * Visualization tools (`re2dot` for regex, graph-based visualizers for policy nodes).

It keeps all of the “how do you compile SBPL?” logic in one place and leaves analysis to other tools.
