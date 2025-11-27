## 1. What this example is about

This example is a tiny, concrete illustration of the “Scheme → compiled profile blob” step inside Seatbelt:

* You write a sandbox profile in SBPL (`profiles/demo.sb`).
* `libsandbox` parses and evaluates it with TinyScheme.
* `libsandbox` returns a compiled binary “policy graph” blob.
* The demo C program saves that blob to disk so you can look at it with other tools.

Think of it as a microscope: it doesn’t run anything under the sandbox, it just gives you the opaque compiled profile that the kernel will later enforce.

---

## 2. Layout and basic workflow

Files:

* `profiles/demo.sb` – a small SBPL profile.
* `src/compile_profile.c` – the C “compiler shim” that calls private `libsandbox` functions.
* `Makefile` – builds the shim and wires a `run-demo` target.
* `run-demo.sh` – one-step wrapper to build + compile the profile into a blob.
* `build/` – created by the Makefile; holds the resulting binary (`demo.sb.bin`).

Typical flow:

1. From the example root:

   * `make run-demo`
   * or, equivalently: `make` and then `./run-demo.sh`
2. This:

   * builds `build/compile_profile` (linked against `-lsandbox`),
   * then runs it to compile `profiles/demo.sb` → `build/demo.sb.bin`.
3. The program prints:

   * `profile_type`
   * bytecode length
   * a small hex preview of the first bytes
4. You then use your own tools (e.g., a profile disassembler) to inspect `demo.sb.bin`.

---

## 3. Lessons

- Builds a tiny clang shim that calls `sandbox_compile_file` to turn `profiles/demo.sb` into a compiled blob (`build/demo.sb.bin`), mirroring the SBPL → TinyScheme → binary pipeline in `substrate/Orientation.md` §3.2.
- Output bytecode layout matches the header/op-table/node/regex/literal structure described in `substrate/Appendix.md`; feed the blob to decoders like `sbdis`, `re2dot`, or `resnarf`.
- The demo profile is intentionally permissive enough to compile/run the helper; adjust `profiles/demo.sb` to watch how changes in SBPL affect the compiled graph.


## 4. The SBPL profile: `profiles/demo.sb`

```scheme
(version 1)
(deny default)

; allow basic runtime behavior for the compile demo
(allow process*)
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/dev"))

; allow a user-writable staging area that downstream tools can probe
(allow file-read* (subpath "/tmp/apple-scheme-demo"))
(allow file-write* (subpath "/tmp/apple-scheme-demo"))

; leave most other operations denied (default)
```

Key points:

* `(version 1)` – uses SBPL version 1.
* `(deny default)` – whitelist mode:

  * Anything not explicitly allowed is denied.
* `(allow process*)` – lets the process do basic process operations (exec, fork, etc.), otherwise the demo binary itself would fail early.
* `(allow file-read* ...)` for `/System`, `/usr`, `/dev`:

  * Lets `libsandbox`, the loader, and libc read the system libraries, devices, etc. they need.
* `(allow file-read* / file-write* (subpath "/tmp/apple-scheme-demo"))`:

  * Creates a “playground” directory where a *sandboxed* process using this profile could store artifacts.
  * In this example, it’s mainly documenting a pattern: give your probes a single, clearly bounded writable subtree.

Conceptually, this profile is intentionally minimal: it’s a whitelist that gives just enough file and process capability to let a SBPL-using process function and write output in a controlled location.

---

## 5. Build glue: `Makefile` and `run-demo.sh`

### `Makefile`

```make
CC := clang
CFLAGS := -Wall -Wextra -Wpedantic -O2
LDFLAGS := -lsandbox

BUILD_DIR := build
BIN := $(BUILD_DIR)/compile_profile

.PHONY: all clean run-demo

all: $(BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN): src/compile_profile.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

run-demo: $(BIN)
	./run-demo.sh

clean:
	rm -rf $(BUILD_DIR)
```

What this is doing:

* Uses `clang` with strict warnings and `-O2`.
* Links against the system `libsandbox` (`-lsandbox`).
* Builds a single binary: `build/compile_profile`.
* `run-demo`:

  * Ensures the binary exists.
  * Delegates to `./run-demo.sh` to actually run the demo.
* `clean` wipes the `build/` directory.

The pattern is: **no extra build system complexity**, one binary, one shell script, and everything else is plain C and SBPL.

### `run-demo.sh`

```bash
#!/bin/zsh
set -euo pipefail

# Build the compiler shim and compile the demo SBPL profile into a binary blob.
# This exercises the TinyScheme → compiled policy step using the modern libsandbox entry points.

...

if [[ ! -x "$BIN" ]]; then
  echo "[*] building compiler demo..."
  make -C "$ROOT"
fi

echo "[*] compiling $IN -> $OUT"
"$BIN" "$IN" "$OUT"

echo
echo "[*] bytecode saved to $OUT (use sbdis or other decoders to inspect the graph)."
```

Essentials:

* `set -euo pipefail` makes the script fail fast on:

  * any error (`-e`),
  * unset variables (`-u`),
  * pipeline errors (`pipefail`).
* It:

  * Locates the repo root,
  * Derives input (`profiles/demo.sb`) and output (`build/demo.sb.bin`) paths,
  * Ensures `compile_profile` is built, then runs it.
* Final echo explicitly reminds you that `demo.sb.bin` is meant for *downstream* analysis tools, not for direct use by `sandbox-exec`.

Taken together, `Makefile` + `run-demo.sh` give you a one-command “lab setup” to go from SBPL text → binary policy blob.

---

## 6. The compiler shim: `src/compile_profile.c`

This is the heart of the example: a small C program that calls private `libsandbox` entry points, captures the `sandbox_profile` struct they return, and writes the `bytecode` portion to disk.

### Header and struct

```c
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// These prototypes mirror the private libsandbox entry points that perform the
// TinyScheme/SBPL compilation described in Orientation.md §3.2. The returned
// structure points at the compiled binary profile (header + operation tables +
// node graph + literal/regex tables) that Seatbelt enforces at runtime.
struct sandbox_profile {
  uint32_t profile_type;     // observed as 0 for plain SBPL compilation
  uint32_t reserved;         // padding/reserved
  const void *bytecode;      // compiled policy graph blob
  size_t bytecode_length;    // length in bytes of the blob above
  ...
};
```

Ideas to take away:

* `libsandbox` doesn’t just return raw bytes; it returns a small header struct (`struct sandbox_profile`) plus a pointer/length to the actual compiled policy graph.
* `profile_type` lets Apple multiplex different compilation modes (e.g., raw SBPL vs app-sandbox entitlements), even though this example only sees `0`.
* `bytecode` is opaque to this program:

  * It’s “header + operation tables + node graph + literal/regex tables” as described elsewhere.
  * This program deliberately doesn’t parse it; it just previews and saves it.

Somewhere above `main`, there will also be prototypes like:

```c
int sandbox_compile_file(const char *path,
                         uint64_t flags,
                         struct sandbox_profile **out_profile,
                         char **out_error);

void sandbox_free_profile(struct sandbox_profile *p);
```

These mirror Apple’s private API, but are enough for our experimental use.

### Small helpers: `hex_preview` and `write_bytes`

The helpers are intentionally simple:

* `hex_preview(const void *data, size_t len)`:

  * Casts to `unsigned char *`,
  * Prints the first up-to-32 bytes in grouped hex,
  * Lets you sanity-check that different SBPL edits actually change the compiled blob.

* `write_bytes(const char *path, const void *data, size_t len)`:

  * Opens `path` for binary write,
  * calls `fwrite`,
  * checks for short writes/errors,
  * returns 0 on success and non-zero on failure.

These helpers keep `main` legible and isolate all I/O error-handling.

### `main`: wiring it together

```c
int main(int argc, char *argv[]) {
  const char *in = "profiles/demo.sb";
  const char *out = "build/demo.sb.bin";

  if (argc == 2 && strcmp(argv[1], "--help") == 0) {
    fprintf(stderr,
            "usage: %s [in.sb] [out.sb.bin]\n"
            "  default in: %s\n"
            "  default out: %s\n\n"
            "Compiles SBPL using libsandbox’s TinyScheme front end and writes the\n"
            "compiled policy blob. The resulting bytecode matches the binary layout\n"
            "described in Appendix.md (Binary Profile Formats and Policy Graphs).\n",
            argv[0], in, out);
    return 1;
  }

  if (argc >= 2) in = argv[1];
  if (argc >= 3) out = argv[2];

  char *error = NULL;
  struct sandbox_profile *p = NULL;

  ...
  // call sandbox_compile_* here
  ...

  printf("  profile_type: %" PRIu32 "\n", p->profile_type);
  printf("  bytecode length: %zu bytes\n", p->bytecode_length);
  hex_preview(p->bytecode, p->bytecode_length);

  if (write_bytes(out, p->bytecode, p->bytecode_length) == 0) {
    printf("[+] wrote compiled profile to %s\n", out);
  }

  sandbox_free_profile(p);
  free(error);
  return 0;
}
```

Flow:

1. Sets defaults for `in` and `out` matching the rest of the example.
2. Handles `--help` with a clear usage message and brief explanation.
3. Allows `in` and `out` to be overridden via CLI arguments.
4. Calls the appropriate `sandbox_compile_*` function:

   * If the call fails, it prints the `error` string and exits.
5. On success:

   * Prints `profile_type` and `bytecode_length`,
   * Runs `hex_preview` to show a small slice of the compiled profile,
   * Writes the full `bytecode` region to the requested output file.
6. Frees both the returned profile and the error string.

The structure of `main` is deliberately linear and boring: almost all of the interesting work is done inside `libsandbox`.

---

## 7. How to use this as a learning scaffold

Ways to learn from and extend this example:

1. **Tweak the SBPL and observe diffs**

   * Edit `profiles/demo.sb`:

     * add or remove `(allow file-read* ...)` lines,
     * change paths, add new operations.
   * Run `make run-demo` again and compare:

     * `bytecode length`,
     * hex preview.
   * This helps you build intuition about how much structural change each SBPL edit induces.

2. **Point at other profiles**

   * Copy in a system profile from `/System/Library/Sandbox/Profiles` as `profiles/foo.sb`.
   * Run: `build/compile_profile profiles/foo.sb build/foo.sb.bin`.
   * Use the same downstream tools to inspect or compare it.

3. **Wrap this in your own probes**

   * Treat `build/demo.sb.bin` as a reproducible artifact:

     * check it into a corpus,
     * feed it into a disassembler or graph visualizer,
     * or compare across OS versions to detect format drift.

Conceptually, this example is about **bridging the gap** between the high-level SBPL text you can read and the low-level compiled policy blob the kernel actually enforces. The files here give you a minimal, self-contained harness to explore that bridge.