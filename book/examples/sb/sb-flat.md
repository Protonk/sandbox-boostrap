## 1. What this example is about

This example is a **mini end-to-end pipeline** for a sandbox profile:

* Author SBPL in `sample.sb`.
* Compile it to a binary policy blob using `libsandbox` in `compile_sample.py`.
* Immediately hand that blob to the **shared profile ingestion layer** (`book/api/profile_tools/ingestion.py`) instead of doing ad-hoc parsing.
* Produce `build/sample.sb.bin`, which you can then decode with `sbdis`, `resnarf`, `re2dot`, etc.

It’s the “hello world” for your **modern graph-based profile format** and the Axis 4.1 ingestion code.

---

## 2. How to run and expected outputs

From the `sb/` example directory:

```sh
./run-demo.sh
```

`run-demo.sh`:

* Enforces strict shell behavior (`set -euo pipefail`).
* Computes `ROOT` (the directory of the script).
* Runs:

  ```sh
  python3 "$ROOT/compile_sample.py"
  ```

On success you’ll see:

* A line saying `compiled sample.sb -> build/sample.sb.bin`.
* Profile metadata (type, length, preview bytes).
* A parsed header summary from the ingestion layer.
* Then:

  ```text
  [*] Output: /path/to/.../build/sample.sb.bin
      Feed this into sbdis/resnarf/re2dot to explore headers, filters, and regexes.
  ```

This gives you a concrete `.sb.bin` artifact plus a sanity check that the ingestion layer can parse it.

---

## 3. The compiler + ingestion glue (`compile_sample.py`)

### 3.1 Repo wiring and struct

```python
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from book.api.profile_tools import ingestion as ingestion
```

* Walks up to the repo root.
* Appends that to `sys.path` so it can import `book.api.profile_tools.ingestion`.
* This is how the example hooks into the shared ingestion layer instead of re-implementing header parsing locally.

The `SandboxProfile` struct mirrors the `libsandbox` C struct:

```python
class SandboxProfile(ctypes.Structure):
    _fields_ = [
        ("profile_type", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("bytecode", ctypes.c_void_p),
        ("bytecode_length", ctypes.c_size_t),
    ]
```

Fields:

* `profile_type` – format/mode indicator from `libsandbox`.
* `bytecode` / `bytecode_length` – pointer and length of the compiled blob.

### 3.2 Calling `libsandbox` to compile

```python
def compile_profile(src: Path, out: Path):
    lib = ctypes.CDLL("libsandbox.dylib")
    lib.sandbox_compile_file.argtypes = [
        ctypes.c_char_p,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    lib.sandbox_compile_file.restype = ctypes.POINTER(SandboxProfile)
    lib.sandbox_free_profile.argtypes = [ctypes.POINTER(SandboxProfile)]
    lib.sandbox_free_profile.restype = None
```

This:

* Loads `libsandbox.dylib`.
* Describes:

  * `sandbox_compile_file(const char *path, uint64_t flags, char **errorbuf)` → `SandboxProfile *`.
  * `sandbox_free_profile(SandboxProfile *)`.

Then:

```python
    err = ctypes.c_char_p()
    profile = lib.sandbox_compile_file(str(src).encode(), 0, ctypes.byref(err))
    if not profile:
        detail = err.value.decode() if err.value else "unknown error"
        raise SystemExit(f"compile failed: {detail}")
```

* Passes the SBPL filename to `sandbox_compile_file`.
* Uses `err` as an error buffer.
* Exits with a helpful message if compilation fails.

On success, extract the blob:

```python
    blob = ctypes.string_at(profile.contents.bytecode, profile.contents.bytecode_length)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)
```

* Copies `bytecode_length` bytes from the `bytecode` pointer into a Python `bytes`.
* Ensures the output directory exists.
* Writes `build/sample.sb.bin`.

Then print a small summary and a hex preview:

```python
    print(f"[+] compiled {src} -> {out}")
    print(f"    profile_type={profile.contents.profile_type} length={profile.contents.bytecode_length}")
    preview = blob[:32]
    grouped = ["".join(f"{b:02x}" for b in preview[i : i + 8]) for i in range(0, len(preview), 8)]
    print(f"    preview: {' '.join(grouped)}")
```

This gives you:

* A quick fingerprint for regressions/diffs.
* Confidence that the blob is non-trivial.

### 3.3 Using the shared ingestion layer

Instead of parsing the binary header in this script, it hands off to `profile_ingestion`:

```python
    # Parse header/sections via Axis 4.1 ingestion layer to avoid ad hoc parsing here.
    blob_wrapper = ingestion.ProfileBlob(bytes=blob, source="examples-sb")
    header = ingestion.parse_header(blob_wrapper)
    sections = ingestion.slice_sections(blob_wrapper, header)
    print(
        "    header: format={fmt} ops={ops} nodes={nodes} "
        "op_table_bytes={ot} node_bytes={nn} regex_literal_bytes={rl}".format(
            fmt=header.format_variant,
            ops=header.operation_count,
            nodes=header.node_count,
            ot=len(sections.op_table),
            nn=len(sections.nodes),
            rl=len(sections.regex_literals),
        )
    )
```

Workflow:

1. Wrap the raw blob in a `ProfileBlob` with a source tag (`"examples-sb"`).
2. Call `parse_header`:

   * Extracts header fields like `format_variant`, `operation_count`, `node_count`.
3. Call `slice_sections`:

   * Returns a struct with slices:

     * `op_table` (operation table bytes),
     * `nodes` (policy graph nodes),
     * `regex_literals` (regex/literal table region).

It then prints a compact header summary:

* `format=<variant>` – modern graph format variant.
* `ops=<operation_count>`.
* `nodes=<node_count>`.
* Byte lengths of each major section.

This demonstrates:

* The ingestion layer works on a simple sample profile.
* `sbdis` and other tools can be migrated to use the same path, instead of duplicating parsing logic.

Finally, cleanup:

```python
    lib.sandbox_free_profile(profile)
    if err:
        libc = ctypes.CDLL(None)
        libc.free(err)
```

* Frees the `SandboxProfile` via `sandbox_free_profile`.
* Frees the error buffer via `libc.free` if it was allocated.

### 3.4 Script entry point

```python
if __name__ == "__main__":
    src = Path(__file__).parent / "sample.sb"
    out = Path(__file__).parent / "build" / "sample.sb.bin"
    compile_profile(src, out)
```

* Uses `sample.sb` in the same directory as input.
* Writes output under `sb/build/`.

This is the piece `run-demo.sh` calls.

---

## 4. The sample SBPL profile (`sample.sb`)

```scheme
(version 1)
(deny default)

; allow basic runtime and library access
(allow process*)
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/dev"))

; demo paths
(allow file-read* (subpath "/tmp/sb-demo"))
(allow file-write* (require-all
                     (subpath "/tmp/sb-demo")
                     (require-not (vnode-type SYMLINK))))

; explicit deny to illustrate literal filters
(deny file-read* (literal "/etc/hosts"))
```

Key features:

1. **Baseline policy**

   * `(version 1)` and `(deny default)`:

     * Default is “deny everything unless explicitly allowed”.

   * `(allow process*)`:

     * Lets the process perform the basic process operations needed to run.

2. **Read access to core system directories**

   * `file-read*` allowed for:

     * `/System`
     * `/usr`
     * `/dev`

   * This mirrors a typical minimal runtime policy: read shared libraries, binaries, and device nodes without granting write access.

3. **Demo directory with write policy and metafilter use**

   * `(allow file-read* (subpath "/tmp/sb-demo"))`:

     * Allow reads under a dedicated demo directory.

   * `(allow file-write* (require-all (subpath "/tmp/sb-demo") (require-not (vnode-type SYMLINK))))`:

     * Allow writes only when:

       * path is under `/tmp/sb-demo` **and**
       * vnode type is **not** `SYMLINK`.

   * This reuses the metafilter patterns from `metafilter-tests`:

     * `require-all` = logical AND.
     * `require-not` = logical NOT around `vnode-type`.
     * Combined, you get: “allow writes only to non-symlink entries under this subpath.”

   * It demonstrates how more expressive path + vnode filters compile into the policy graph the ingestion layer sees.

4. **Explicit deny with literal**

   * `(deny file-read* (literal "/etc/hosts"))`:

     * Even if other rules might implicitly cover `file-read*` of `/etc`, this literal deny makes `/etc/hosts` a concrete negative example.
     * In the compiled graph, you’ll see this show up as a `file-read*` op with a `literal` predicate.

Overall, `sample.sb` is deliberately small but showcases:

* Default-deny structure.
* Allow rules using `subpath`.
* Metafilters (`require-all`, `require-not`) with `vnode-type`.
* A literal-path deny.

This makes it a good target for decoding tests and graph inspection.

---

## 5. Lessons (`lessons.md`) and how this fits the ecosystem

`lessons.md` summarizes the point:

* This example:

  * Compiles `sample.sb` using `libsandbox`.
  * Then defers all binary layout understanding to the **shared ingestion layer** instead of re-parsing headers by hand.
* The ingestion layer is currently focused on the **modern graph-based format**.
* Other consumers (e.g., `sbdis/`) can and should be migrated to reuse this layer.

Practically:

* `sb/` gives you:

  * A canonical sample SBPL profile.
  * A reproducible path to a `.sb.bin`.
  * A confirmation that `profile_ingestion` can parse and slice it.

* Downstream examples (`sbdis`, `re2dot`, `resnarf`) can use `build/sample.sb.bin` as:

  * A test case while you develop disassemblers and visualizers.
  * A known-good artifact for regression tests and cross-tool comparisons.

Reading `compile_sample.py`, `sample.sb`, and `lessons.md` together shows the full arc:

SBPL text → `libsandbox` compile → binary blob → ingestion header/sections → downstream decoders.
