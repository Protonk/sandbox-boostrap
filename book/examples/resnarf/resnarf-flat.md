## 1. What this example is about

This example is a **regex extractor** for early-format sandbox profiles:

* Input: a legacy compiled profile (`*.sb.bin`) using the old **decision-tree layout** (Blazakis-era).
* Output: one or more `*.re` files, each containing a compiled AppleMatch regex blob.
* Purpose: let you pull regex blobs out of historical profiles so you can:

  * archive them,
  * diff them across OS versions,
  * feed them into tools like `re2dot.py` to visualize their NFAs.

Modern “bundled / graph” profile formats are deliberately **not** handled here; this script is scoped to the older format where the regex table is at a simple, documented location in the header.

You can think of `resnarf.py` as the **front half** of a pipeline:

`old_profile.sb.bin  →  resnarf.py  →  *.re blobs  →  re2dot.py / other analysis`

---

## 2. How to run it

Single file:

* `resnarf.py`

Usage (as a CLI):

```sh
./resnarf.py profile.sb.bin output_dir
```

Where:

* `profile.sb.bin` is a compiled sandbox profile in the **early decision-tree format**.
* `output_dir` is a directory where extracted regex blobs will be written. It will be created if it does not exist.

Example:

```sh
./resnarf.py /path/to/bsd.sb.bin ./regexes
```

You should see output like:

```text
[+] wrote ./regexes/bsd.sb.bin.000.re (352 bytes)
[+] wrote ./regexes/bsd.sb.bin.001.re (196 bytes)
...
```

Each `.re` file is a single regex blob suitable for feeding into `re2dot.py` or your own NFA tooling.

If you run the script with the wrong number of arguments, you get a short usage message and a reference to Appendix §3 (“Binary Profile Formats and Policy Graphs”), which is where the layout is defined.

---

## 3. Header layout and what “early format” means

The docstring at the top summarizes the scope:

```python
"""
Extract compiled regex blobs from a sandbox profile.

Supports the early decision-tree format (Blazakis-era) where the header stores
`re_table_offset` (in 8-byte words) and `re_table_count`. Modern bundled/graph
formats require additional parsing and are not handled here.
"""
```

Key points:

* **Early decision-tree format**:

  * The header starts with two 16-bit little-endian values:

    * `re_table_offset_words`
    * `re_table_count`
  * The regex table lives at `re_table_offset_words * 8` bytes from the start of the file.
  * The table itself is a simple array of 16-bit offsets in 8-byte words, each pointing at one regex blob.

* **Modern graph formats**:

  * Store regex tables differently (bundled/profile graphs).
  * This script does not attempt to parse them.

So this script is explicitly for **legacy profiles** where `re_table_offset` and `re_table_count` live at the start of the file as 16-bit fields.

---

## 4. Core extractor: `extract_regexes`

```python
def extract_regexes(profile_path: Path, out_dir: Path):
    data = profile_path.read_bytes()
    if len(data) < 4:
        raise SystemExit("file too small to contain regex table header")
```

Step 1: read the entire profile into memory and sanity-check that it’s at least large enough to hold the two 16-bit header fields (4 bytes).

### 4.1 Reading the regex table header

```python
    re_table_offset_words, re_count = struct.unpack_from("<HH", data, 0)
    re_table_offset = re_table_offset_words * 8
    if re_table_offset >= len(data):
        raise SystemExit("re_table_offset outside file; unsupported format?")
```

* Interpret the first 4 bytes of the profile as **little-endian**:

  * `<HH` → two unsigned 16-bit integers (`H`).
  * `re_table_offset_words`: location of the regex table, in units of 8-byte words.
  * `re_count`: number of regex entries.

* Convert the offset from words to bytes:

  * `re_table_offset = re_table_offset_words * 8`.

* If this computed offset is outside the file, the profile is not in the expected format, and the script exits with an explanatory error.

This mirrors the layout described in Appendix §3 for early profiles.

### 4.2 Reading regex offsets from the table

```python
    re_offsets = []
    for i in range(re_count):
        off_words = struct.unpack_from("<H", data, re_table_offset + i * 2)[0]
        re_offsets.append(off_words * 8)
```

The regex table itself:

* Starts at `re_table_offset`.
* Contains `re_count` entries.
* Each entry is a 16-bit **word offset** (`<H`) from the start of the file.
* Each entry is multiplied by 8 to get the byte offset of a regex record.

So after this loop:

* `re_offsets` is a list of byte offsets where each regex blob’s record begins.

Conceptually:

* Early profiles: “header → table of offsets → (offset, length, blob) for each regex.”

---

## 5. Extracting each regex blob

```python
    out_dir.mkdir(parents=True, exist_ok=True)
    for idx, offset in enumerate(re_offsets):
        if offset + 4 > len(data):
            print(f"[skip] regex {idx}: offset outside file")
            continue
        length = struct.unpack_from("<I", data, offset)[0]
        start = offset + 4
        end = start + length
        if end > len(data):
            print(f"[skip] regex {idx}: length outside file")
            continue
        blob = data[start:end]
        out_path = out_dir / f"{profile_path.name}.{idx:03d}.re"
        out_path.write_bytes(blob)
        print(f"[+] wrote {out_path} ({len(blob)} bytes)")
```

For each regex entry:

1. Ensure there’s room to read at least a 4-byte length at `offset`.

   * If `offset + 4 > len(data)`, skip this regex and print a warning.

2. Read the length (little-endian 32-bit):

   * `length = struct.unpack_from("<I", data, offset)[0]`.

3. Compute the blob’s byte range:

   * Payload starts at `start = offset + 4`.
   * Ends at `end = start + length`.

4. If `end` is outside the file, skip with a warning.

5. Otherwise:

   * Slice the blob: `blob = data[start:end]`.

   * Compute an output filename:

     * `<profile_path.name>.<idx:03d>.re`.

     Example: `bsd.sb.bin.002.re`.

   * Write the blob to disk.

   * Print a summary line with path and size.

Error handling:

* Corrupted or unexpected entries are **skipped**, not fatal:

  * The script continues with the next regex.
* This is intentional: you can still recover valid blobs even if some entries are broken.

---

## 6. CLI wrapper: `main()`

```python
def main():
    if len(sys.argv) != 3:
        print("usage:")
        print("  resnarf.py profile.sb.bin output_dir")
        print()
        print("Extracts regex blobs from early-format sandbox profiles (Appendix.md:")
        print('"Binary Profile Formats and Policy Graphs" §3).')
        sys.exit(1)

    profile = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    extract_regexes(profile, out_dir)
```

* Checks that you provided exactly two arguments.
* Prints usage and a short description including the Appendix reference.
* Converts arguments to `Path` objects.
* Calls `extract_regexes`.

Standard Python `if __name__ == "__main__": main()` wiring at the bottom makes this behave like a regular CLI tool.

---

## 7. How this fits in the larger sandbox workflow

In the context of the other examples:

* `resnarf.py`:

  * operates on old `*.sb.bin` profiles using the **decision-tree** layout,
  * extracts compiled regex blobs into standalone `.re` files.

* `re2dot.py`:

  * takes `.re` files as input,
  * parses the AppleMatch NFA,
  * emits `.dot` graphs so you can visualize regex structure.

A practical workflow:

1. **Extract regexes from a legacy profile**:

   ```sh
   ./resnarf.py legacy_profile.sb.bin ./legacy_regexes
   ```

2. **Visualize one of the extracted regexes**:

   ```sh
   ./re2dot.py ./legacy_regexes/legacy_profile.sb.bin.000.re -o regex0.dot
   dot -Tpng regex0.dot -o regex0.png
   ```

3. **Compare across versions**:

   * Run `resnarf.py` on the same profile from different OS versions.
   * Diff the `.re` blobs or their `.dot` graphs to see how regex-based filters evolved.

Conceptually, `resnarf.py` is the **regex-table extractor** for the early binary formats described in Appendix §3, giving you access to regex internals that are otherwise buried inside `*.sb.bin` profiles.
