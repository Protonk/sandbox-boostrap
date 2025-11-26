## 1. What this example is about

This example shows both halves of the `libsandbox` story:

1. **Compilation path**: inline SBPL → `sandbox_compile_string` → compiled profile blob.
2. **Application path**: compiled profile → `sandbox_apply` → “try to sandbox this process”.

On modern macOS, you should expect the **apply step to fail** without the right entitlements / SIP configuration. That is the point: the demo makes visible that:

* `sandbox_apply` exists and is callable.
* But on a stock system, it is not generally available to arbitrary processes, even if they can compile profiles.

You can read this example as a minimal “compile + apply probe” for `libsandbox`.

---

## 2. Build and run flow

Files:

* `src/sandbox_calls_demo.c` – the demo itself.
* `Makefile` – builds `build/sandbox_calls_demo`.
* `run-demo.sh` – makes sure it’s built, then runs it.

From the example root:

```sh
# One-shot run
./run-demo.sh
```

That script:

1. Builds `build/sandbox_calls_demo` via `make` if missing.
2. Runs `build/sandbox_calls_demo`.

You should see:

* Confirmation that inline SBPL compiled.
* The `profile_type`, bytecode length, and a hex preview of the compiled profile.
* A `sandbox_apply` result, usually an error, with `errno` explaining that activation is blocked.

---

## 3. Build glue: `Makefile` and `run-demo.sh`

### `Makefile`

```make
CC := clang
CFLAGS := -Wall -Wextra -Wpedantic -O2
LDFLAGS := -lsandbox

BUILD_DIR := build
BIN := $(BUILD_DIR)/sandbox_calls_demo
```

* Uses `clang` with strict warnings and `-O2`.
* Links against `libsandbox` (`-lsandbox`) directly.

Targets:

```make
all: $(BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN): src/sandbox_calls_demo.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
```

* `all` builds a single binary.
* `$(BUILD_DIR)` target ensures `build/` exists.
* The binary is built from one C file, linked with `-lsandbox`.

Utility targets:

```make
run-demo: $(BIN)
	./run-demo.sh

clean:
	rm -rf $(BUILD_DIR)
```

* `run-demo` defers to the shell script.
* `clean` wipes `build/`.

The point: the build is deliberately minimal; all the interesting work is in `sandbox_calls_demo.c`.

### `run-demo.sh`

```bash
#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN="$ROOT/build/sandbox_calls_demo"

if [[ ! -x "$BIN" ]]; then
  make -C "$ROOT"
fi

echo "[*] running sandbox_calls_demo"
"$BIN"
```

* Uses strict shell flags for robustness.
* Locates the `build/sandbox_calls_demo` binary relative to the script.
* Runs `make` in the example root if the binary doesn’t exist.
* Executes the demo.

Net effect: `./run-demo.sh` is the entry point you use; it hides the build details.

---

## 4. The demo: `sandbox_calls_demo.c`

### 4.1 Private interface declarations

At the top:

```c
struct sandbox_profile {
  uint32_t profile_type;
  uint32_t reserved;
  const void *bytecode;
  size_t bytecode_length;
};

extern struct sandbox_profile *sandbox_compile_string(const char *profile,
                                                      uint64_t flags,
                                                      char **errorbuf);
extern void sandbox_free_profile(struct sandbox_profile *profile);
extern int sandbox_apply(struct sandbox_profile *profile);
```

This is the same `sandbox_profile` struct seen in other examples:

* `profile_type` – mode of the compiled profile.
* `bytecode` + `bytecode_length` – pointer/length to the compiled policy blob.

The functions:

* `sandbox_compile_string`:

  * Takes SBPL text in `profile`.
  * Returns a compiled `sandbox_profile *` or `NULL` on error.
  * Optionally fills `errorbuf` with diagnostic text.
* `sandbox_free_profile`:

  * Frees the `sandbox_profile` and its internal allocations.
* `sandbox_apply`:

  * Attempts to apply the given profile to the **current process**.
  * On modern systems, this typically requires privileges / entitlements.

These are **private APIs**: they are not declared in public headers; you declare them yourself based on reverse-engineered signatures.

---

### 4.2 Hex preview helper

```c
static void hex_preview(const void *data, size_t len) {
  const unsigned char *b = (const unsigned char *)data;
  size_t preview = len < 32 ? len : 32;
  printf("  first %zu bytes:", preview);
  for (size_t i = 0; i < preview; ++i) {
    if (i % 8 == 0) printf(" ");
    printf("%02x", b[i]);
  }
  printf("\n");
}
```

This prints:

* “first N bytes:” where `N` is `min(len, 32)`.
* The bytes in hex, grouped by 8 per space.

It’s a quick way to confirm that:

* The profile compiled.
* Different SBPL strings produce different binary front-ends.

---

### 4.3 SBPL source and compilation

```c
int main(void) {
  const char *profile_src =
      "(version 1)\n"
      "(deny default)\n"
      "(allow process*)\n"
      "(allow file-read* (subpath \"/System\"))\n";
```

The inline SBPL is a tiny whitelist:

* `(version 1)` – SBPL version.
* `(deny default)` – deny everything by default.
* `(allow process*)` – allow process operations (so the process can start and run).
* `(allow file-read* (subpath "/System"))` – allow reads under `/System`.

This is minimal but realistic: enough to let a process live and read from the system root, while leaving most other operations denied.

Compile it:

```c
  char *error = NULL;
  struct sandbox_profile *p = sandbox_compile_string(profile_src, 0, &error);
  if (p == NULL) {
    fprintf(stderr, "[-] sandbox_compile_string failed: %s\n",
            error ? error : "unknown error");
    free(error);
    return 1;
  }
```

* `sandbox_compile_string` takes:

  * the SBPL string,
  * flags (0 here),
  * pointer to an error buffer.
* If compilation fails:

  * Error text is printed (if any),
  * `error` is freed,
  * the program exits.

On success:

```c
  printf("[+] compiled inline SBPL\n");
  printf("  profile_type: %" PRIu32 "\n", p->profile_type);
  printf("  bytecode length: %zu bytes\n", p->bytecode_length);
  hex_preview(p->bytecode, p->bytecode_length);
```

This makes the compilation result visible:

* `profile_type` lets you see which mode you hit.
* `bytecode length` confirms the blob exists and has nontrivial size.
* `hex_preview` helps spot changes if you later tweak `profile_src`.

Conceptually, this is the **SBPL → compiled graph** step again, but with inline text instead of a file.

---

### 4.4 Probing `sandbox_apply`

The key second half:

```c
  // Demonstrate that sandbox_apply is present but may be blocked by SIP/entitlements.
  int rv = sandbox_apply(p);
  if (rv != 0) {
    printf("[!] sandbox_apply returned %d (errno=%d: %s)\n", rv, errno,
           strerror(errno));
    printf("    On modern macOS this is expected without the right entitlements.\n");
  } else {
    printf("[+] sandbox_apply succeeded (sandbox now active for this process)\n");
  }
```

Here the program:

* Calls `sandbox_apply(p)` with the compiled profile.
* Checks the return value and `errno`.

Two cases:

1. **Failure (expected on stock systems)**:

   * Prints `[!] sandbox_apply returned ...` with `errno` and a human-readable error string.
   * Explains that this is expected without the right entitlements.
   * This demonstrates that:

     * The apply API is present and callable.
     * But enforcement of “who may apply profiles” is external (SIP, entitlements, etc.).

2. **Success (in specially configured environments)**:

   * Prints that `sandbox_apply` succeeded and the sandbox is now active for the current process.
   * In that scenario, all subsequent syscalls from this process are evaluated under the new profile.

The example is not trying to get you into the success case; it’s instead showing the **boundary**: “compile is easy; apply is restricted.”

---

### 4.5 Cleanup

At the end:

```c
  sandbox_free_profile(p);
  free(error);
  return 0;
}
```

* Frees the `sandbox_profile` using `sandbox_free_profile`.
* Frees the `error` buffer if it was allocated (even on success, some implementations may still allocate or reuse buffers).

This keeps the demo clean and avoids leaks in repeated runs.

---

## 5. How to use this example for learning

This example is most useful if you treat it as a **two-step probe**:

1. **Compile-only experiments**

   * Edit `profile_src`:

     * add more `(allow ...)` rules,
     * change paths, operations, or version.
   * Rebuild and run via `./run-demo.sh`.
   * Observe:

     * `profile_type` (does it change?),
     * `bytecode length`,
     * hex preview.
   * This helps you develop a sense of how SBPL structure translates into binary size and shape.

2. **Apply boundary experiments**

   * On a stock machine, observe and record the `sandbox_apply` error.
   * If you have a controlled environment where `sandbox_apply` can succeed (e.g., special entitlements, different boot setup), compare:

     * Before/after behavior of the process (e.g., additional probes for file access).
     * `errno` and return codes in each context.

Conceptually, you come away with:

* A concrete picture of the **private compiler interface** (`sandbox_compile_string`).
* A concrete picture of the **private apply interface** (`sandbox_apply`).
* An understanding that:

  * Compiling SBPL is broadly accessible in userland (if you can load `libsandbox`).
  * Actually **attaching** that profile to a running process is tightly controlled by system policy.

This example complements the others that focus purely on compilation: it adds the “what if I try to use `libsandbox` as a userland sandbox launcher?” question, and shows that the answer is “you hit entitlement / SIP gates,” which is a key part of the modern Seatbelt threat model.
